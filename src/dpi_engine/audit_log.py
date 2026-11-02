"""The immutable audit log (`T6-06`): an append-only chain a reader can check.

**Why this exists.** The store (`T6-01`) makes a policy version immutable and the
queue (`T6-05`) makes a human's decision durable, but neither answers the
question asked after an incident: *what was applied, when, by whom, and on what
evidence?* This module is that record. It is written by the one apply door and
by nothing else, so a change that moves an active version and a change that
leaves an entry are the same event rather than two calls that can disagree.

**Every entry names the same seven facts.** Who (`actor`), when (`applied_at`),
which agent, which run (`runs`, derived from the citations), which evidence
(`citations`), which prompt version, and which model version. They are fields,
not prose: a reader answers each question without parsing a sentence, and the
hash covers them, so an answer cannot be edited without breaking the chain.

**Append-only with a hash chain.** Each entry's hash is a SHA-256 over its whole
content *including the previous entry's hash*, so changing one line breaks that
line and deleting one breaks the line after it. A separate head anchor names the
count and the last hash; deleting the *last* entry is invisible to the chain
alone, and the anchor is what catches it. `AuditLog.verify_chain` is the reader
that refuses an edited entry, a deleted middle entry, a deleted last entry, a
reordered log, a blank line, a torn append and a foreign schema.

**The honest limit.** A hash chain cannot detect truncation of the whole log
*together with* its anchor file, because there is nothing outside the directory
to compare against. An external anchor -- a remote witness, a signed checkpoint
-- is a deployment concern rather than a file format, and this module does not
pretend a local file supplies it. What it does supply is the property the write
path needs: an applied change cannot be quietly rewritten, and a log that does
not verify is refused rather than appended to.

**Nothing here applies anything.** There is no rule manager and no store write in
this module. It records a `PolicyVersion` that `T6-06`'s apply door has already
committed and activated; importing this module cannot change policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dpi_engine.blast_radius import Tier
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_store import (
    PolicyKind,
    PolicyVersion,
    RuleStoreError,
    canonical_json,
    is_version_id,
    policy_kind_of,
    write_json_atomic,
)

__all__ = [
    "AUTO_ACTOR",
    "GENESIS_HASH",
    "SCHEMA",
    "AuditLog",
    "AuditLogError",
    "AuditRecord",
]

#: The on-disk shape of one entry. A later binary reads this or refuses it; an
#: entry is never half-read through meanings it did not have when written.
SCHEMA = "dpi-engine-audit/v1"

#: The `prev_hash` of the first entry. A real hash is never all zeroes in
#: practice, so "this is the beginning" is distinguishable from "this follows an
#: entry whose hash happens to look like zeros".
GENESIS_HASH = "0" * 64

#: The actor recorded when no human was needed. Auto-apply is a signature-table
#: change that the breaker cleared, so the engine is the accountable party and
#: the record says so instead of borrowing a person's name.
AUTO_ACTOR = "engine:auto-apply"

_HASH_LENGTH = 64
_HASH_ALPHABET = frozenset("0123456789abcdef")

_RECORD_KEYS = frozenset(
    {
        "schema",
        "sequence",
        "prev_hash",
        "applied_at",
        "actor",
        "tier",
        "request_id",
        "proposal_digest",
        "version_id",
        "kind",
        "agent_version",
        "prompt_version",
        "model_version",
        "citations",
        "hash",
    }
)

_HEAD_KEYS = frozenset({"schema", "count", "last_hash"})


class AuditLogError(ValueError):
    """An entry, the head anchor, or an append is not usable.

    A `ValueError` so it joins the engine's other malformed-input errors, and
    named so a caller can tell "this log does not verify" from "this directory
    is unreadable".
    """


def _require_hash(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HASH_LENGTH
        or any(char not in _HASH_ALPHABET for char in value)
    ):
        raise AuditLogError(
            f"{field} must be {_HASH_LENGTH} lowercase hex characters, got {value!r}"
        )
    return value


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not is_version_id(value):
        raise AuditLogError(
            f"{field} must be 16 lowercase hex characters, got {value!r}"
        )
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditLogError(
            f"{field} must be a non-empty string, got {value!r}. The audit trail "
            "records which agent, prompt and model produced a change."
        )
    return value


def _content(
    *,
    sequence: int,
    prev_hash: str,
    applied_at: str,
    actor: str,
    tier: Tier,
    request_id: str | None,
    proposal_digest: str,
    version_id: str,
    kind: PolicyKind,
    agent_version: str,
    prompt_version: str,
    model_version: str,
    citations: tuple[Citation, ...],
) -> dict[str, Any]:
    """Everything the hash covers, in one place.

    Both `AuditRecord.content` and `AuditLog.append` go through this function.
    A second assembly of the same record would be a hash input that could drift
    by one field, which is the one bug this type cannot afford.
    """
    return {
        "schema": SCHEMA,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "applied_at": applied_at,
        "actor": actor,
        "tier": tier.value,
        "request_id": request_id,
        "proposal_digest": proposal_digest,
        "version_id": version_id,
        "kind": kind.value,
        "agent_version": agent_version,
        "prompt_version": prompt_version,
        "model_version": model_version,
        "citations": [citation.to_json() for citation in citations],
    }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One applied change, chained to the entry before it.

    Every instance is internally consistent, however it was constructed: the
    fields are validated, the tier and request id are required to agree (an
    auto-apply has no request, a human tier has one), and `hash` is checked
    against a fresh hash of the contents. `from_json` is the door a reader uses;
    it refuses an edited entry rather than repairing it.
    """

    sequence: int
    prev_hash: str
    applied_at: str
    actor: str
    tier: Tier
    request_id: str | None
    proposal_digest: str
    version_id: str
    kind: PolicyKind
    agent_version: str
    prompt_version: str
    model_version: str
    citations: tuple[Citation, ...]
    hash: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise AuditLogError(
                "sequence must be a non-negative integer, got "
                f"{self.sequence!r}"
            )
        _require_hash(self.prev_hash, "prev_hash")
        _require_text(self.applied_at, "applied_at")
        _require_text(self.actor, "actor")
        _require_hash(self.hash, "hash")

        if not isinstance(self.tier, Tier):
            raise AuditLogError(
                f"tier must be a Tier, got {type(self.tier).__name__}"
            )
        if self.tier is Tier.REFUSED:
            raise AuditLogError(
                f"audit record {self.sequence} is a refused candidate. A refusal "
                "is not an applied change, so it is never recorded as one."
            )
        if self.tier is Tier.AUTO_APPLY:
            if self.request_id is not None:
                raise AuditLogError(
                    "request_id must be None for an auto-apply entry: no human "
                    "requested the change, so naming one would attribute it to a "
                    f"reviewer who never saw it ({self.request_id!r})."
                )
            if self.actor != AUTO_ACTOR:
                raise AuditLogError(
                    "actor must be "
                    f"{AUTO_ACTOR!r} for an auto-apply entry, got {self.actor!r}. "
                    "An automatic change is accountable to the engine, not to a "
                    "person."
                )
            if self.kind is not PolicyKind.SIGNATURES:
                raise AuditLogError(
                    "an auto-apply entry must apply a signatures version: only a "
                    "signature-table change may skip the human gate, got a "
                    f"{self.kind.value} version."
                )
        else:
            if self.request_id is None:
                raise AuditLogError(
                    "request_id is required for a human-approved entry: the record "
                    "must name the request the reviewer decided."
                )
            _require_id(self.request_id, "request_id")

        _require_id(self.proposal_digest, "proposal_digest")
        _require_id(self.version_id, "version_id")
        if not isinstance(self.kind, PolicyKind):
            raise AuditLogError(
                f"kind must be a PolicyKind, got {type(self.kind).__name__}"
            )
        _require_text(self.agent_version, "agent_version")
        _require_text(self.prompt_version, "prompt_version")
        _require_text(self.model_version, "model_version")

        if not isinstance(self.citations, tuple) or not self.citations:
            raise AuditLogError(
                "citations must be a non-empty tuple of Citation records, got "
                f"{self.citations!r}"
            )
        if any(not isinstance(cited, Citation) for cited in self.citations):
            raise AuditLogError(
                "every citation must be a Citation, got "
                f"{[type(cited).__name__ for cited in self.citations]}"
            )

        computed = self.computed_hash
        if self.hash != computed:
            raise AuditLogError(
                f"audit record {self.sequence} claims hash {self.hash}, but its "
                f"contents hash to {computed}. The entry was edited after it was "
                "written."
            )

    @property
    def runs(self) -> tuple[str, ...]:
        """The stored runs this entry's evidence names, deduplicated and sorted."""
        return tuple(sorted({citation.run_id for citation in self.citations}))

    def content(self) -> dict[str, Any]:
        """The hash's input: every fact the entry records, and no hash."""
        return _content(
            sequence=self.sequence,
            prev_hash=self.prev_hash,
            applied_at=self.applied_at,
            actor=self.actor,
            tier=self.tier,
            request_id=self.request_id,
            proposal_digest=self.proposal_digest,
            version_id=self.version_id,
            kind=self.kind,
            agent_version=self.agent_version,
            prompt_version=self.prompt_version,
            model_version=self.model_version,
            citations=self.citations,
        )

    @property
    def computed_hash(self) -> str:
        """The hash this entry's contents produce, regardless of its claim."""
        return hashlib.sha256(
            canonical_json(self.content()).encode("utf-8")
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        """The whole on-disk entry, as JSON-ready data."""
        return self.content() | {"hash": self.hash}

    @classmethod
    def from_json(cls, raw: object) -> AuditRecord:
        """Decodes and re-checks a stored entry. An edit is refused, not repaired."""
        if not isinstance(raw, Mapping):
            raise AuditLogError(
                f"an audit entry must be a JSON object, got {type(raw).__name__}"
            )
        unknown = sorted(set(raw) - _RECORD_KEYS)
        if unknown:
            raise AuditLogError(f"an audit entry has an unknown key {unknown[0]!r}")
        missing = sorted(_RECORD_KEYS - set(raw))
        if missing:
            raise AuditLogError(
                f"an audit entry is missing the {missing[0]!r} key"
            )

        schema = raw["schema"]
        if schema != SCHEMA:
            raise AuditLogError(
                f"this entry is schema {schema!r}, but this build reads {SCHEMA!r}. "
                "An entry is refused rather than read through new field meanings."
            )

        tier_raw = raw["tier"]
        try:
            tier = Tier(tier_raw)
        except (TypeError, ValueError) as exc:
            known = ", ".join(member.value for member in Tier)
            raise AuditLogError(
                f"an audit entry has an unknown tier {tier_raw!r}. Expected one "
                f"of: {known}"
            ) from exc

        kind_raw = raw["kind"]
        try:
            kind = policy_kind_of(kind_raw) if isinstance(kind_raw, str) else kind_raw
        except RuleStoreError as exc:
            raise AuditLogError(
                f"an audit entry has an unknown kind {kind_raw!r}. Expected one "
                f"of: {', '.join(member.value for member in PolicyKind)}"
            ) from exc

        citations_raw = raw["citations"]
        if not isinstance(citations_raw, list):
            raise AuditLogError(
                "an audit entry's citations must be a list, got "
                f"{type(citations_raw).__name__}"
            )

        return cls(
            sequence=raw["sequence"],
            prev_hash=raw["prev_hash"],
            applied_at=raw["applied_at"],
            actor=raw["actor"],
            tier=tier,
            request_id=raw["request_id"],
            proposal_digest=raw["proposal_digest"],
            version_id=raw["version_id"],
            kind=kind,
            agent_version=raw["agent_version"],
            prompt_version=raw["prompt_version"],
            model_version=raw["model_version"],
            citations=tuple(
                Citation.from_json(item) for item in citations_raw
            ),
            hash=raw["hash"],
        )


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class AuditLog:
    """A directory holding one append-only JSONL log and its head anchor.

    Layout::

        <root>/audit.jsonl   one entry per line, oldest first
        <root>/head.json     {schema, count, last_hash}, replaced atomically

    `append` verifies the existing chain before writing, so a log that has
    already been edited is refused rather than extended. `verify_chain` is the
    reader; `rebuild_head` repairs an anchor left behind a torn append, and only
    that, because it re-checks the chain's own hashes first.
    """

    def __init__(
        self, root: str | Path, *, clock: Callable[[], str] | None = None
    ) -> None:
        self._root = Path(root)
        self._clock = _now if clock is None else clock
        self._lock = threading.Lock()

    @property
    def root(self) -> Path:
        """The directory holding this log."""
        return self._root

    @property
    def path(self) -> Path:
        """The append-only entry file."""
        return self._root / "audit.jsonl"

    @property
    def head_path(self) -> Path:
        """The anchor naming the entry count and the last hash."""
        return self._root / "head.json"

    # -- writing ----------------------------------------------------------

    def append(
        self,
        *,
        proposal: Proposal,
        version: PolicyVersion,
        tier: Tier,
        actor: str,
        request_id: str | None = None,
    ) -> AuditRecord:
        """Records one applied change as the next entry in the chain.

        Refusals that must not touch the directory are checked first: a refused
        candidate is not an applied change, an auto-apply has no request and must
        be a signatures version, and a human tier must name the request it
        answers. The version must be the proposal's own commit -- same kind,
        same parent, same id -- so an approval of one proposal cannot be
        recorded against another.
        """
        if not isinstance(proposal, Proposal):
            raise AuditLogError(
                f"an audit entry needs a Proposal, got {type(proposal).__name__}"
            )
        if not isinstance(version, PolicyVersion):
            raise AuditLogError(
                "an audit entry needs the committed PolicyVersion, got "
                f"{type(version).__name__}"
            )
        if not isinstance(tier, Tier):
            raise AuditLogError(
                f"an audit entry needs a Tier, got {type(tier).__name__}"
            )
        if tier is Tier.REFUSED:
            raise AuditLogError(
                "a refused candidate is not an applied change, so it is never "
                "recorded as one."
            )
        if tier is Tier.AUTO_APPLY:
            if request_id is not None:
                raise AuditLogError(
                    "request_id must be None for an auto-apply entry: no human "
                    "requested the change, so naming one would attribute it to a "
                    f"reviewer who never saw it ({request_id!r})."
                )
            if proposal.kind is not PolicyKind.SIGNATURES:
                raise AuditLogError(
                    "an auto-apply entry must apply a signatures version: only a "
                    "signature-table change may skip the human gate, got a "
                    f"{proposal.kind.value} proposal."
                )
        else:
            if request_id is None:
                raise AuditLogError(
                    f"a {tier.value} entry requires the request_id it answers. "
                    "Without it the record names a change but not the decision "
                    "that allowed it."
                )
            _require_id(request_id, "request_id")

        if version.kind is not proposal.kind:
            raise AuditLogError(
                f"the committed version's kind is {version.kind.value}, but the "
                f"proposal's kind is {proposal.kind.value}. An entry records one "
                "proposal and its own commit."
            )
        if version.parent != proposal.parent:
            raise AuditLogError(
                f"the committed version's parent is {version.parent!r}, but the "
                f"proposal's parent is {proposal.parent!r}. A version derived from "
                "another version is not this proposal's result."
            )
        if version.version_id != proposal.version_id:
            raise AuditLogError(
                f"the committed version {version.version_id} is not the version "
                f"the proposal addresses ({proposal.version_id}). The bytes "
                "reviewed must be the bytes applied."
            )

        with self._lock:
            chain = self._read_chain(require_head=True)
            sequence = len(chain)
            prev_hash = chain[-1].hash if chain else GENESIS_HASH
            applied_at = self._clock()
            payload = _content(
                sequence=sequence,
                prev_hash=prev_hash,
                applied_at=applied_at,
                actor=actor,
                tier=tier,
                request_id=request_id,
                proposal_digest=proposal.digest,
                version_id=version.version_id,
                kind=proposal.kind,
                agent_version=proposal.agent_version,
                prompt_version=proposal.prompt_version,
                model_version=proposal.model_version,
                citations=proposal.citations,
            )
            record = AuditRecord(
                sequence=sequence,
                prev_hash=prev_hash,
                applied_at=applied_at,
                actor=actor,
                tier=tier,
                request_id=request_id,
                proposal_digest=proposal.digest,
                version_id=version.version_id,
                kind=proposal.kind,
                agent_version=proposal.agent_version,
                prompt_version=proposal.prompt_version,
                model_version=proposal.model_version,
                citations=proposal.citations,
                hash=hashlib.sha256(
                    canonical_json(payload).encode("utf-8")
                ).hexdigest(),
            )
            self._append_line(record)
            self._write_head(record)
        return record

    def _append_line(self, record: AuditRecord) -> None:
        """Adds one whole line, with the newline, before the anchor moves."""
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(record.to_json(), sort_keys=True, ensure_ascii=False)
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditLogError(f"cannot append to {self.path}: {exc}") from exc

    def _write_head(self, record: AuditRecord) -> None:
        self._publish_head(count=record.sequence + 1, last_hash=record.hash)

    def _publish_head(self, *, count: int, last_hash: str) -> None:
        try:
            write_json_atomic(
                self.head_path,
                {"schema": SCHEMA, "count": count, "last_hash": last_hash},
            )
        except RuleStoreError as exc:
            raise AuditLogError(
                f"cannot write the head anchor {self.head_path}: {exc}. The entry "
                "is on disk; call `rebuild_head` once the directory is writable."
            ) from exc

    # -- reading ----------------------------------------------------------

    def verify_chain(self) -> tuple[AuditRecord, ...]:
        """Every entry, in order, after checking the chain and its anchor."""
        return self._read_chain(require_head=True)

    def applied_digests(self) -> frozenset[str]:
        """The digests of every proposal this log records as applied.

        The write door uses this to refuse a replay. It verifies the chain first,
        so a forged entry cannot whitelist a second application of a change.
        """
        return frozenset(record.proposal_digest for record in self.verify_chain())

    def rebuild_head(self) -> AuditRecord | None:
        """Rewrites the anchor from a chain whose entries still verify.

        This repairs exactly one failure: a crash between the line append and the
        anchor write. It re-checks every entry's hash and link first, so it
        cannot launder an edited log into a verified one.
        """
        with self._lock:
            chain = self._read_chain(require_head=False)
            last = chain[-1] if chain else None
            self._publish_head(
                count=len(chain),
                last_hash=GENESIS_HASH if last is None else last.hash,
            )
            return last

    def _read_chain(self, *, require_head: bool) -> tuple[AuditRecord, ...]:
        records = self._read_records()
        if require_head:
            self._check_head(records)
        return records

    def _read_records(self) -> tuple[AuditRecord, ...]:
        """The entries alone: hashes, sequences and links, but not the anchor."""
        if not self.path.exists():
            return ()
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditLogError(f"cannot read {self.path}: {exc}") from exc
        if not text:
            return ()
        if not text.endswith("\n"):
            raise AuditLogError(
                f"{self.path} does not end with a newline: its last entry is "
                "incomplete. An entry is written whole, so this is a torn append "
                "rather than a record."
            )

        lines = text.split("\n")[:-1]
        records: list[AuditRecord] = []
        previous = GENESIS_HASH
        for index, line in enumerate(lines):
            if not line.strip():
                raise AuditLogError(
                    f"{self.path} has a blank line at entry {index}. A blank line "
                    "is not an entry, and skipping it would hide whatever follows."
                )
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditLogError(
                    f"entry {index} in {self.path} is not valid JSON: {exc}"
                ) from exc
            record = AuditRecord.from_json(raw)
            if record.sequence != index:
                raise AuditLogError(
                    f"entry {index} in {self.path} claims sequence "
                    f"{record.sequence}. Entries are contiguous, so a gap is a "
                    "deleted entry."
                )
            if record.prev_hash != previous:
                raise AuditLogError(
                    f"entry {index} in {self.path} chains to {record.prev_hash}, "
                    f"but the entry before it hashes to {previous}. The chain is "
                    "broken: an entry was edited, deleted or reordered."
                )
            records.append(record)
            previous = record.hash
        return tuple(records)

    def _check_head(self, records: tuple[AuditRecord, ...]) -> None:
        if not self.head_path.exists():
            if not records:
                return
            raise AuditLogError(
                f"the head anchor {self.head_path} is missing, so a deleted last "
                "entry cannot be detected. Refusing to call the log verified."
            )
        try:
            raw = json.loads(self.head_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuditLogError(
                f"{self.head_path} is not valid JSON: {exc}"
            ) from exc
        except OSError as exc:
            raise AuditLogError(f"cannot read {self.head_path}: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise AuditLogError(f"{self.head_path} does not contain a JSON object")

        unknown = sorted(set(raw) - _HEAD_KEYS)
        if unknown:
            raise AuditLogError(
                f"the head anchor has an unknown key {unknown[0]!r}"
            )
        missing = sorted(_HEAD_KEYS - set(raw))
        if missing:
            raise AuditLogError(
                f"the head anchor is missing the {missing[0]!r} key"
            )
        if raw["schema"] != SCHEMA:
            raise AuditLogError(
                f"the head anchor is schema {raw['schema']!r}, but this build "
                f"reads {SCHEMA!r}"
            )

        count = raw["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise AuditLogError(
                f"the head anchor's count must be a non-negative integer, got "
                f"{count!r}"
            )
        last_hash = _require_hash(raw["last_hash"], "the head anchor's last_hash")

        expected_last = records[-1].hash if records else GENESIS_HASH
        if count != len(records) or last_hash != expected_last:
            raise AuditLogError(
                f"the head anchor {self.head_path} says {count} entries ending at "
                f"{last_hash}, but the log holds {len(records)} ending at "
                f"{expected_last}. An entry was deleted or appended without its "
                "anchor; refusing to call the log verified."
            )
