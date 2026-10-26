"""The policy store: versioned, content-addressed, append-only (`T6-01`).

**Why this exists.** Phase 6 writes policy, and every write has to answer the
same three questions afterwards: *what exactly changed, who asked for it, and
what was in force before?* A mutable rules file answers none of them. This store
answers all three by making a **version** the unit: the canonical policy
document, its provenance, an optional note naming the parent it was derived
from, and a digest over exactly those bytes. The digest is the version id, so a
file whose contents no longer agree with its name is refused rather than
silently trusted.

**Two documents, one shape.** The build writes two policies: the blocking
ruleset (`RuleManager.to_dict`) and the signature table
(`SignatureTable.to_json`). They have different schemas and different
validators, and this store deliberately does not add a third. Validation is
delegated to the loader each document already owns -- `RuleManager.from_dict`
and `SignatureTable.from_json` -- because a second validator would drift from
the first and the two would disagree exactly when a rule matters. What the
store adds is *normalisation*: the loader is run, its canonical output is
stored, and a partial document and its completed form therefore have one
identity. The ruleset's live `version` counter is a property of an in-memory
manager, not of a policy, so it is stripped.

**What "immutable" means here.** A version file is written once, under
`os.replace`, and never rewritten. `load` refuses a document, provenance
record, note, parent or kind that no longer hashes to the id it claims. This is
content addressing, not cryptography: someone who can rewrite the directory can
also recompute a digest, and that is a different threat, closed by `T6-06`'s
append-only audit chain rather than pretended away here. The property this
store does provide is the one the human gate needs -- *the bytes reviewed are
the bytes applied* -- because `T6-02`'s proposal digest is checked against these
bytes.

**A revert is a new version.** `restore` does not delete the versions after the
one being restored. It commits the old document as a *new* version whose parent
is the version restored, so both the change and the undo are visible in
`history`, in order. `activate` is the only operation that moves the active
pointer, one kind at a time; nothing in this module writes to a live process.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from dpi_engine.rule_manager import Provenance, RuleManager, RuleManagerError
from dpi_engine.signatures import SignatureTable

__all__ = [
    "SCHEMA",
    "PolicyKind",
    "PolicyVersion",
    "RuleStore",
    "RuleStoreError",
]

#: The on-disk schema of a version record and of the active pointer. Both move
#: together: a v2 record read by a v1 binary is refused, not half-read.
SCHEMA = "dpi-engine-rulestore/v1"

#: A version id addresses a file, so it is validated before use. Same shape as
#: the run store's ids: an id is data supplied by a caller, and
#: `load("../../etc/passwd")` must be a bad argument rather than a traversal.
_VERSION_ID_LENGTH = 16
_VERSION_ID_ALPHABET = frozenset("0123456789abcdef")

_RECORD_KEYS = frozenset(
    {
        "schema",
        "version_id",
        "kind",
        "parent",
        "document",
        "provenance",
        "note",
        "created_at",
    }
)

_ACTIVE_KEYS = frozenset({"schema", "active"})


class RuleStoreError(ValueError):
    """A stored version, the pointer, or a proposed commit is not usable.

    A `ValueError` so the store's refusals join the engine's other
    malformed-input errors; named so callers can distinguish "this policy is
    wrong" from "this directory is unreadable".
    """


class PolicyKind(StrEnum):
    """Which policy a version holds.

    The values are persisted in the record and in `active.json`, so they are
    part of the file format: renaming one is a migration, not a refactor.
    """

    RULESET = "ruleset"
    SIGNATURES = "signatures"


def _kind(value: PolicyKind | str) -> PolicyKind:
    try:
        return PolicyKind(value)
    except ValueError as exc:
        known = ", ".join(kind.value for kind in PolicyKind)
        raise RuleStoreError(
            f"unknown policy kind {value!r}. Expected one of: {known}"
        ) from exc


def _is_version_id(value: str) -> bool:
    """True when `value` is exactly 16 lowercase hex characters."""
    return len(value) == _VERSION_ID_LENGTH and all(
        char in _VERSION_ID_ALPHABET for char in value
    )


def _canonical(payload: Mapping[str, Any]) -> str:
    """One spelling of a payload, so a digest does not depend on key order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: Mapping[str, Any]) -> str:
    """The content address of a version: a digest, shortened to a file name."""
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[
        :_VERSION_ID_LENGTH
    ]


def _copy_document(document: object) -> dict[str, Any]:
    """A detached, JSON-only copy of a document.

    Deep-copied through JSON rather than `copy.deepcopy` because a policy
    document is defined as JSON data. An object that cannot make that round trip
    is not storable, and finding that out at `commit` is better than finding out
    when the file is read back.
    """
    if not isinstance(document, dict):
        raise RuleStoreError(
            f"a policy document must be a JSON object, got {type(document).__name__}"
        )
    try:
        copied: dict[str, Any] = json.loads(_canonical(document))
    except (TypeError, ValueError) as exc:
        raise RuleStoreError(f"a policy document must be JSON data: {exc}") from exc
    return copied


def _content_payload(
    kind: PolicyKind,
    parent: str | None,
    document: Mapping[str, Any],
    provenance: Provenance | None,
    note: str,
) -> dict[str, Any]:
    """Everything a version *is*, as opposed to when it was published.

    `created_at` is deliberately absent. It is the publication time, not
    content: including it would make an identical re-commit a new version,
    which would turn an idempotent retry into a fabricated change. The
    provenance's own `created_at` *is* content, because it records when the
    proposal was made rather than when this directory received it.
    """
    return {
        "schema": SCHEMA,
        "kind": kind.value,
        "parent": parent,
        "document": document,
        "provenance": None if provenance is None else provenance.to_dict(),
        "note": note,
    }


def _normalise_document(kind: PolicyKind, document: object) -> dict[str, Any]:
    """Validates a document with its own loader and returns its canonical form.

    The ruleset's `version` key is a live counter on an in-memory manager.
    Keeping it would make two identical policies differ merely because a
    manager had seen more edits, so it is removed here.
    """
    if not isinstance(document, dict):
        raise RuleStoreError(
            f"a {kind.value} document must be a JSON object, got "
            f"{type(document).__name__}"
        )
    try:
        if kind is PolicyKind.RULESET:
            normalised = RuleManager.from_dict(document, source="<rule store>").to_dict()
            normalised.pop("version", None)
            return normalised
        return SignatureTable.from_json(document).to_json()
    except (RuleManagerError, TypeError, ValueError) as exc:
        raise RuleStoreError(
            f"the {kind.value} document is not valid: {exc}"
        ) from exc


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    """Publishes `payload` at `path` under `os.replace`.

    The temporary file is in the same directory, so the replace is a rename
    rather than a copy, and a reader never sees a half-written record. `fsync`
    before the replace is the same ordering the run store uses: without it a
    crash can leave the rename durable and the contents not.
    """
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise RuleStoreError(f"cannot write {path}: {exc}") from exc


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    """One immutable, content-addressed policy version.

    `version_id` is a field as well as a digest so the file can say which
    version it claims to be; `load` checks that claim against both the file name
    and a fresh hash. `document` is deep-copied on construction, so mutating the
    dict a caller passed in cannot change the version that was committed.
    """

    version_id: str
    kind: PolicyKind
    parent: str | None
    document: dict[str, Any]
    provenance: Provenance | None
    note: str
    created_at: str

    def __post_init__(self) -> None:
        if not _is_version_id(self.version_id):
            raise RuleStoreError(
                f"{self.version_id!r} is not a version id. Expected 16 lowercase hex "
                "characters."
            )
        if not isinstance(self.kind, PolicyKind):
            raise RuleStoreError(f"unknown policy kind {self.kind!r}")
        if self.parent is not None and not _is_version_id(self.parent):
            raise RuleStoreError(
                f"{self.parent!r} is not a version id. A parent names a stored version."
            )
        if not isinstance(self.note, str):
            raise RuleStoreError(
                f"note must be a string, got {type(self.note).__name__}"
            )
        if not isinstance(self.created_at, str) or not self.created_at:
            raise RuleStoreError("created_at must be a non-empty timestamp string")
        object.__setattr__(self, "document", _copy_document(self.document))

    def content(self) -> dict[str, Any]:
        """The digest's input: everything that makes this version itself."""
        return _content_payload(
            self.kind, self.parent, self.document, self.provenance, self.note
        )

    @property
    def computed_id(self) -> str:
        """The id this version's content hashes to, regardless of what it claims."""
        return _digest(self.content())

    def to_json(self) -> dict[str, Any]:
        """The whole on-disk record, as JSON-ready data."""
        return {
            "schema": SCHEMA,
            "version_id": self.version_id,
            "kind": self.kind.value,
            "parent": self.parent,
            "document": _copy_document(self.document),
            "provenance": None if self.provenance is None else self.provenance.to_dict(),
            "note": self.note,
            "created_at": self.created_at,
        }

    @classmethod
    def from_json(cls, raw: object) -> PolicyVersion:
        """Decodes and type-checks a record. Integrity is `RuleStore.load`'s job.

        The split is deliberate: this method answers "is this the shape of a
        version?", and `load` answers "is this the version its name claims?".
        Both refusals use `RuleStoreError`, because a caller should not have to
        distinguish a malformed file from an edited one to know the store is
        unusable.
        """
        if not isinstance(raw, Mapping):
            raise RuleStoreError(
                f"a version record must be a JSON object, got {type(raw).__name__}"
            )
        unknown = sorted(set(raw) - _RECORD_KEYS)
        if unknown:
            raise RuleStoreError(f"a version record has an unknown key {unknown[0]!r}")
        missing = sorted(_RECORD_KEYS - set(raw))
        if missing:
            raise RuleStoreError(f"a version record is missing the {missing[0]!r} key")

        schema = raw["schema"]
        if schema != SCHEMA:
            raise RuleStoreError(
                f"this record is schema {schema!r}, but this build reads {SCHEMA!r}. "
                "A record is refused rather than read through new field meanings."
            )

        version_id = raw["version_id"]
        if not isinstance(version_id, str) or not _is_version_id(version_id):
            raise RuleStoreError(
                f"{version_id!r} is not a version id. Expected 16 lowercase hex "
                "characters."
            )

        kind = _kind(raw["kind"]) if isinstance(raw["kind"], str) else raw["kind"]
        if not isinstance(kind, PolicyKind):
            raise RuleStoreError(f"unknown policy kind {kind!r}")

        parent = raw["parent"]
        if parent is not None and (
            not isinstance(parent, str) or not _is_version_id(parent)
        ):
            raise RuleStoreError(
                f"{parent!r} is not a version id. A parent names a stored version."
            )

        provenance_raw = raw["provenance"]
        if provenance_raw is None:
            provenance = None
        else:
            provenance = Provenance.from_dict(provenance_raw)
            if provenance is None:
                # Distinct from "no provenance": an unreadable record must not
                # silently become an anonymous version, or the audit trail would
                # lose a rule's origin without anyone noticing.
                raise RuleStoreError(
                    "the provenance record is unreadable. Refusing rather than "
                    "dropping it: an anonymous version would be indistinguishable "
                    "from one that was never attributed."
                )

        note = raw["note"]
        if not isinstance(note, str):
            raise RuleStoreError(f"note must be a string, got {type(note).__name__}")

        created_at = raw["created_at"]
        if not isinstance(created_at, str) or not created_at:
            raise RuleStoreError("created_at must be a non-empty timestamp string")

        return cls(
            version_id=version_id,
            kind=kind,
            parent=parent,
            document=_copy_document(raw["document"]),
            provenance=provenance,
            note=note,
            created_at=created_at,
        )


class RuleStore:
    """A directory of immutable policy versions, plus one pointer per kind.

    Layout::

        <root>/versions/<version_id>.json   one record per version
        <root>/active.json                  which version each kind is on

    `history` reads every version file. That is the right cost for a directory
    whose versions are written a few times a day and read whole; the operation
    whose cost grows is named here rather than discovered later.
    """

    def __init__(
        self, root: str | Path, *, clock: Callable[[], str] | None = None
    ) -> None:
        self._root = Path(root)
        self._clock = clock if clock is not None else _now
        self._lock = threading.Lock()

    @property
    def root(self) -> Path:
        return self._root

    # -- addressing -------------------------------------------------------

    def path_for(self, version_id: str) -> Path:
        """The file backing `version_id`, validated against traversal.

        The id reaches this store from an agent's proposal in a later task, so
        it is data, not a trusted path component.
        """
        if not _is_version_id(version_id):
            raise RuleStoreError(
                f"{version_id!r} is not a version id. Expected 16 lowercase hex "
                "characters, as returned by `commit` or `history`."
            )
        return self._root / "versions" / f"{version_id}.json"

    # -- writing ----------------------------------------------------------

    def commit(
        self,
        kind: PolicyKind | str,
        document: object,
        *,
        provenance: Provenance | None = None,
        note: str = "",
        parent: str | None = None,
    ) -> PolicyVersion:
        """Validates and stores `document` as a new version, or returns the existing one.

        Idempotent for identical content: the same document, provenance, note
        and parent address the same file, and the second call returns the stored
        version with its original publication time. That is what makes a retried
        apply safe; a *different* provenance timestamp is content, and mints a
        distinct version, because it records a different proposal.
        """
        policy_kind = _kind(kind)
        if provenance is not None and not isinstance(provenance, Provenance):
            raise RuleStoreError(
                "provenance must be a Provenance record or None, got "
                f"{type(provenance).__name__}"
            )
        if not isinstance(note, str):
            raise RuleStoreError(f"note must be a string, got {type(note).__name__}")

        normalised = _normalise_document(policy_kind, document)

        if parent is not None:
            parent_version = self.load(parent)
            if parent_version.kind is not policy_kind:
                raise RuleStoreError(
                    f"parent {parent} is a {parent_version.kind.value} version, but "
                    f"this commit is a {policy_kind.value} version. A version's "
                    "history is its own kind."
                )

        version = PolicyVersion(
            version_id=_digest(
                _content_payload(policy_kind, parent, normalised, provenance, note)
            ),
            kind=policy_kind,
            parent=parent,
            document=normalised,
            provenance=provenance,
            note=note,
            created_at=self._clock(),
        )

        path = self.path_for(version.version_id)
        if path.exists():
            existing = self.load(version.version_id)
            if existing.content() != version.content():
                raise RuleStoreError(
                    f"version {version.version_id} is already stored with different "
                    "content. Version ids are content-addressed, so this means either "
                    "a hash collision or a nondeterministic normaliser. Neither can "
                    "be resolved by overwriting, and doing so would hide it."
                )
            return existing

        _write_atomic(path, version.to_json())
        return version

    def restore(
        self,
        kind: PolicyKind | str,
        version_id: str,
        *,
        provenance: Provenance | None = None,
        note: str = "",
    ) -> PolicyVersion:
        """Commits an old version's document as a new version with that parent.

        Not a rollback: the versions changed after the target remain in
        `history`, and the revert itself is a version that names what it undid.
        The caller supplies the revert's provenance, because the record of who
        reverted is not the record of who originally proposed.
        """
        policy_kind = _kind(kind)
        target = self.load(version_id)
        if target.kind is not policy_kind:
            raise RuleStoreError(
                f"{version_id} is a {target.kind.value} version and cannot be "
                f"restored as a {policy_kind.value} version."
            )
        return self.commit(
            policy_kind,
            target.document,
            provenance=provenance,
            note=note,
            parent=version_id,
        )

    def activate(self, version_id: str) -> PolicyVersion:
        """Moves one kind's active pointer to `version_id` and returns that version.

        The pointer is written atomically, and only after the target has loaded:
        a pointer to a version this store cannot read would make every later
        `active` call fail, so it is never published.
        """
        with self._lock:
            version = self.load(version_id)
            pointers = self._read_active()
            pointers[version.kind] = version.version_id
            _write_atomic(
                self._root / "active.json",
                {
                    "schema": SCHEMA,
                    "active": {
                        kind.value: pointers.get(kind) for kind in PolicyKind
                    },
                },
            )
        return version

    # -- reading ----------------------------------------------------------

    def load(self, version_id: str) -> PolicyVersion:
        """Reads one version, refusing an edited file rather than repairing it."""
        path = self.path_for(version_id)
        if not path.exists():
            raise RuleStoreError(
                f"no version {version_id} in {self._root}. Call `history` to see what "
                "is stored."
            )
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuleStoreError(
                f"{path} is not valid JSON: {exc}. A version is written atomically, "
                "so a truncated file was corrupted outside this store rather than "
                "left behind by a failed write."
            ) from exc
        if not isinstance(raw, dict):
            raise RuleStoreError(f"{path} does not contain a JSON object")

        version = PolicyVersion.from_json(raw)

        if version.version_id != version_id:
            raise RuleStoreError(
                f"{path} is filed as {version_id} but claims {version.version_id}. "
                "The name and the record disagree about which version this is."
            )

        computed = version.computed_id
        if computed != version.version_id:
            raise RuleStoreError(
                f"{path} claims version {version.version_id}, but its contents hash "
                f"to {computed}. The file has been edited since it was written; "
                "trusting either id would apply policy that was never reviewed."
            )

        # A record can be internally consistent and still hold a document the
        # loader would refuse. Normalising again costs one small parse and keeps
        # the store from handing a consumer policy it cannot use.
        normalised = _normalise_document(version.kind, version.document)
        if _canonical(normalised) != _canonical(version.document):
            raise RuleStoreError(
                f"{path} does not hold a canonical {version.kind.value} document. "
                "A stored document is written in canonical form, so a different "
                "form means it was replaced outside this store."
            )

        return version

    def history(
        self, kind: PolicyKind | str | None = None
    ) -> tuple[PolicyVersion, ...]:
        """Every stored version, oldest first, optionally narrowed to one kind.

        Raises on any unreadable file. Skipping a bad version would make the
        store look tidier than it is, and "what changed before this?" would
        silently get an answer that omits the change in question.
        """
        policy_kind = None if kind is None else _kind(kind)
        versions_dir = self._root / "versions"
        if not versions_dir.exists():
            return ()

        versions = [self.load(path.stem) for path in sorted(versions_dir.glob("*.json"))]
        selected = [
            version
            for version in versions
            if policy_kind is None or version.kind is policy_kind
        ]
        return tuple(
            sorted(selected, key=lambda version: (version.created_at, version.version_id))
        )

    def active(self, kind: PolicyKind | str) -> PolicyVersion | None:
        """The version this kind is currently on, or `None` if it never moved."""
        policy_kind = _kind(kind)
        return self._version_at(self._read_active().get(policy_kind))

    # -- the active pointer ----------------------------------------------

    def _read_active(self) -> dict[PolicyKind, str | None]:
        """The pointer file as data, strictly. A missing file is an empty pointer."""
        path = self._root / "active.json"
        if not path.exists():
            return {}
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuleStoreError(
                f"{path} is not readable JSON: {exc}. Refusing rather than treating "
                "a damaged pointer as 'nothing is active'."
            ) from exc
        if not isinstance(raw, dict):
            raise RuleStoreError(f"{path} does not contain a JSON object")

        unknown = sorted(set(raw) - _ACTIVE_KEYS)
        if unknown:
            raise RuleStoreError(f"{path} has an unknown key {unknown[0]!r}")
        missing = sorted(_ACTIVE_KEYS - set(raw))
        if missing:
            raise RuleStoreError(f"{path} is missing the {missing[0]!r} key")
        if raw["schema"] != SCHEMA:
            raise RuleStoreError(
                f"{path} is schema {raw['schema']!r}, but this build reads {SCHEMA!r}"
            )

        active = raw["active"]
        if not isinstance(active, dict):
            raise RuleStoreError(f"{path} has no 'active' object")

        pointers: dict[PolicyKind, str | None] = {}
        for name, value in active.items():
            pointer_kind = _kind(name)
            if value is None:
                pointers[pointer_kind] = None
                continue
            if not isinstance(value, str) or not _is_version_id(value):
                raise RuleStoreError(
                    f"{path} names {value!r} for {pointer_kind.value}, which is not a "
                    "version id."
                )
            pointers[pointer_kind] = value
        return pointers

    def _version_at(self, version_id: str | None) -> PolicyVersion | None:
        return None if version_id is None else self.load(version_id)
