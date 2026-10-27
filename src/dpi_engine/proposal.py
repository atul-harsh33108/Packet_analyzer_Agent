"""The signed proposal: validated policy, evidence, and one digest (`T6-02`).

**Why this exists.** `T6-01` made policy versioned and immutable, but nothing
yet carried a *request to change it*. The request has two jobs. Before a human
sees it, its document must be valid and its evidence must exist: a malformed
rule that reaches a reviewer is a malformed change one approval away from
production, and a citation that points at no stored flow is a claim nobody can
check. After approval, the bytes reviewed must be the bytes applied: the
proposal's digest covers the commit and its evidence, and `apply` recomputes it
rather than trusting the queue's copy.

**"Signed" means content-bound, not cryptographically keyed.** The digest is a
SHA-256 over the canonical record: the policy document, its provenance, the
note, the parent, the citations, and the agent, prompt and model versions. It
proves the record was not edited after it was built. It does **not** prove who
built it. Someone who can rewrite the queue can recompute a digest, and that is
a different threat, closed by `T6-06`'s append-only audit chain rather than
pretended away here. A keyed signature would add forgery resistance against
exactly the attacker who can already write the store; claiming that property
without key management would be worse than not claiming it.

**One id formula.** `version_id` is the id `RuleStore.commit` will mint for this
document, provenance, note and parent. It is computed by the store's own
`version_id_for`, not by a second implementation, so "this proposal's policy is
this store version" is a fact rather than two calculations that happen to agree
today. `apply` checks both ids: the digest binds the review, the version id
binds the commit.

**Evidence is a pointer, deliberately.** A citation is a run id and a
five-tuple, resolved through the `CitationResolver` port. The digest binds the
pointer, not a snapshot of the flow row: the run store is content-addressed and
refuses an edited record, so the pointer is stable, while freezing a decoded
feature vector here would make a proposal's identity depend on a codec's
rendering. Citation *order* is not content either; `build` sorts the evidence so
two proposals over the same set are the same proposal.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from dpi_engine.rule_manager import Provenance
from dpi_engine.rule_store import (
    PolicyKind,
    RuleStoreError,
    canonical_document,
    canonical_json,
    copy_document,
    digest_of,
    policy_kind_of,
    version_id_for,
)
from dpi_engine.types import FiveTuple, FlowRecord

__all__ = [
    "SCHEMA",
    "Citation",
    "CitationResolver",
    "Proposal",
    "ProposalError",
]

#: The on-disk schema of a proposal record. A proposal is persisted by the
#: queue (`T6-05`), so this moves with the record's shape.
SCHEMA = "dpi-engine-proposal/v1"

#: Ids (run ids, store version ids, proposal digests) share one shape. The
#: check is duplicated here rather than imported from the run store: a proposal
#: is policy data, and importing the run store would pull the pipeline into
#: every caller that only wants to validate a document.
_ID_LENGTH = 16
_ID_ALPHABET = frozenset("0123456789abcdef")

_RECORD_KEYS = frozenset(
    {
        "schema",
        "digest",
        "version_id",
        "kind",
        "document",
        "provenance",
        "note",
        "parent",
        "citations",
        "agent_version",
        "prompt_version",
        "model_version",
    }
)

_CITATION_KEYS = frozenset(
    {"run_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
)

#: IPv4 addresses are stored as unsigned 32-bit integers on `FiveTuple`; ports
#: and the IP protocol field have their own widths. A citation outside these
#: ranges is not a flow that can exist, so it is refused at the door rather
#: than sent to a resolver that can only return `None`.
_IPV4_MAX = 2**32 - 1
_FIVE_TUPLE_LIMITS: tuple[tuple[str, int], ...] = (
    ("src_ip", _IPV4_MAX),
    ("dst_ip", _IPV4_MAX),
    ("src_port", 65535),
    ("dst_port", 65535),
    ("protocol", 255),
)


class ProposalError(ValueError):
    """A proposal, its evidence, or a stored proposal record is not usable.

    A `ValueError` so a malformed proposal joins the engine's other
    malformed-input errors; named so a caller can distinguish "this change is
    wrong" from "the store could not be read".
    """


def _is_hex_id(value: str) -> bool:
    """True when `value` is exactly 16 lowercase hex characters."""
    return len(value) == _ID_LENGTH and all(
        char in _ID_ALPHABET for char in value
    )


def _require_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not _is_hex_id(value):
        raise ProposalError(
            f"{value!r} is not a {what}. Expected 16 lowercase hex characters."
        )
    return value


def _coerce_kind(value: object) -> PolicyKind:
    if not isinstance(value, str):
        raise ProposalError(f"unknown policy kind {value!r}")
    try:
        return policy_kind_of(value)
    except RuleStoreError as exc:
        raise ProposalError(str(exc)) from exc


def _canonical_document(kind: PolicyKind, document: object) -> dict[str, Any]:
    try:
        return canonical_document(kind, document)
    except RuleStoreError as exc:
        raise ProposalError(str(exc)) from exc


def _version_id(
    kind: PolicyKind,
    document: object,
    provenance: Provenance,
    note: str,
    parent: str | None,
) -> str:
    try:
        return version_id_for(
            kind,
            document=document,
            provenance=provenance,
            note=note,
            parent=parent,
        )
    except RuleStoreError as exc:
        raise ProposalError(str(exc)) from exc


def _require_provenance(value: object) -> Provenance:
    if not isinstance(value, Provenance):
        raise ProposalError(
            "a proposal requires provenance: a Provenance record with a source "
            f"and an author. Got {type(value).__name__}."
        )
    return value


def _require_note(value: object) -> str:
    if not isinstance(value, str):
        raise ProposalError(f"note must be a string, got {type(value).__name__}")
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProposalError(
            f"{field} must be a non-empty string, got {value!r}. The audit trail "
            "records which agent, prompt and model produced a proposal."
        )
    return value


def _ordered_citations(value: object) -> tuple[Citation, ...]:
    if not isinstance(value, (tuple, list)):
        raise ProposalError(
            "citations must be a list of Citation records, got "
            f"{type(value).__name__}"
        )
    if not value:
        raise ProposalError(
            "a proposal must cite at least one flow: a policy change with no "
            "evidence cannot be reviewed"
        )
    non_citations = [item for item in value if not isinstance(item, Citation)]
    if non_citations:
        raise ProposalError(
            "every citation must be a Citation, got "
            f"{type(non_citations[0]).__name__}"
        )
    if len(set(value)) != len(value):
        raise ProposalError("a proposal cites the same flow twice")
    # Citation order is presentation, not content: the evidence is a set. Two
    # proposals over the same flows are the same proposal even if an agent
    # listed them in a different order on a retry.
    return tuple(sorted(value, key=lambda cited: (cited.run_id, cited.five_tuple)))


@dataclass(frozen=True, slots=True)
class Citation:
    """One flow, in one stored run, that a proposal offers as evidence.

    A run id and a five-tuple rather than a flow snapshot: the run store is
    content-addressed, so this names immutable evidence. `to_json` flattens the
    tuple the way `query_flows` rows are flattened, with the run id alongside,
    so an agent that has just read the rows can copy one and cite it.
    """

    run_id: str
    five_tuple: FiveTuple

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not _is_hex_id(self.run_id):
            raise ProposalError(
                f"{self.run_id!r} is not a run id. Expected 16 lowercase hex "
                "characters, as returned by `RunStore.save` or `list_runs`."
            )
        if not isinstance(self.five_tuple, FiveTuple):
            raise ProposalError(
                "a citation's flow must be a FiveTuple, got "
                f"{type(self.five_tuple).__name__}"
            )
        for name, maximum in _FIVE_TUPLE_LIMITS:
            value = getattr(self.five_tuple, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ProposalError(
                    f"citation.{name} must be an integer, got {value!r}"
                )
            if not 0 <= value <= maximum:
                raise ProposalError(
                    f"citation.{name} must be between 0 and {maximum}, got {value}"
                )

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "src_ip": self.five_tuple.src_ip,
            "dst_ip": self.five_tuple.dst_ip,
            "src_port": self.five_tuple.src_port,
            "dst_port": self.five_tuple.dst_port,
            "protocol": self.five_tuple.protocol,
        }

    @classmethod
    def from_json(cls, raw: object) -> Citation:
        if not isinstance(raw, Mapping):
            raise ProposalError(
                f"a citation must be a JSON object, got {type(raw).__name__}"
            )
        unknown = sorted(set(raw) - _CITATION_KEYS)
        if unknown:
            raise ProposalError(f"a citation has an unknown key {unknown[0]!r}")
        missing = sorted(_CITATION_KEYS - set(raw))
        if missing:
            raise ProposalError(f"a citation is missing the {missing[0]!r} key")

        run_id = raw["run_id"]
        if not isinstance(run_id, str):
            raise ProposalError(
                f"a citation's run_id must be a string, got {type(run_id).__name__}"
            )
        values: dict[str, int] = {}
        for name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
            value = raw[name]
            if not isinstance(value, int) or isinstance(value, bool):
                raise ProposalError(
                    f"a citation's {name} must be an integer, got {value!r}"
                )
            values[name] = value
        return cls(run_id=run_id, five_tuple=FiveTuple(**values))


class CitationResolver(Protocol):
    """The port `build` resolves evidence through.

    `RunStore.flow(run_id, five_tuple)` is the expected production shape; a
    test can pass an in-memory table. `None` means the run does not hold that
    flow, which `build` treats as a refusal rather than an error: "this citation
    points at nothing" is exactly the fabrication the check exists to stop.
    """

    def resolve(self, citation: Citation) -> FlowRecord | None:
        """The flow `citation` names, or `None` if the run never held it."""
        ...


def _content(
    *,
    version_id: str,
    kind: PolicyKind,
    document: Mapping[str, Any],
    provenance: Provenance,
    note: str,
    parent: str | None,
    citations: tuple[Citation, ...],
    agent_version: str,
    prompt_version: str,
    model_version: str,
) -> dict[str, Any]:
    """Everything the digest covers, in one place.

    Both `build` and `Proposal.content` go through this function. A second
    assembly of the same record would be a digest input that could drift by one
    field, which is the one bug this type cannot afford.
    """
    return {
        "schema": SCHEMA,
        "version_id": version_id,
        "kind": kind.value,
        "document": copy_document(document),
        "provenance": provenance.to_dict(),
        "note": note,
        "parent": parent,
        "citations": [citation.to_json() for citation in citations],
        "agent_version": agent_version,
        "prompt_version": prompt_version,
        "model_version": model_version,
    }


@dataclass(frozen=True, slots=True)
class Proposal:
    """One reviewed change: a policy commit, its evidence, and its identity.

    Every instance is internally consistent, however it was constructed.
    `__post_init__` checks the document is canonical, keeps the loader's
    canonical copy of it (so the value does not alias the record it was decoded
    from), orders the citations, checks the version id against the store's
    formula and the digest against the record, so a `Proposal` that exists is one
    whose fields agree with its ids. `build` is the normal door because it also
    *resolves* the evidence; `from_json` is the door a queue uses, and it refuses
    an edited record.
    """

    digest: str
    version_id: str
    kind: PolicyKind
    document: dict[str, Any]
    provenance: Provenance
    note: str
    parent: str | None
    citations: tuple[Citation, ...]
    agent_version: str
    prompt_version: str
    model_version: str

    def __post_init__(self) -> None:
        _require_id(self.digest, "proposal digest")
        _require_id(self.version_id, "version id")
        if not isinstance(self.kind, PolicyKind):
            raise ProposalError(f"unknown policy kind {self.kind!r}")
        _require_provenance(self.provenance)
        _require_note(self.note)
        _require_text(self.agent_version, "agent_version")
        _require_text(self.prompt_version, "prompt_version")
        _require_text(self.model_version, "model_version")
        if self.parent is not None:
            _require_id(self.parent, "version id")

        object.__setattr__(self, "citations", _ordered_citations(self.citations))

        normalised = _canonical_document(self.kind, self.document)
        try:
            stored = canonical_json(self.document)
        except (TypeError, ValueError) as exc:
            raise ProposalError(
                f"a proposal document must be JSON data: {exc}"
            ) from exc
        if stored != canonical_json(normalised):
            raise ProposalError(
                f"the proposal's {self.kind.value} document is not canonical. A "
                "proposal stores the document its loader produces, so a different "
                "form was edited outside this path."
            )
        object.__setattr__(self, "document", normalised)

        expected_version = _version_id(
            self.kind, normalised, self.provenance, self.note, self.parent
        )
        if self.version_id != expected_version:
            raise ProposalError(
                f"proposal version id {self.version_id} is not the version its "
                f"contents would mint ({expected_version}). The proposal was edited "
                "after it was built."
            )
        if self.digest != self.computed_digest:
            raise ProposalError(
                f"proposal digest {self.digest} does not match its contents "
                f"({self.computed_digest}). An edited proposal is refused rather "
                "than queued for review."
            )

    def content(self) -> dict[str, Any]:
        """The digest's input: the commit, its evidence, and its producers."""
        return _content(
            version_id=self.version_id,
            kind=self.kind,
            document=self.document,
            provenance=self.provenance,
            note=self.note,
            parent=self.parent,
            citations=self.citations,
            agent_version=self.agent_version,
            prompt_version=self.prompt_version,
            model_version=self.model_version,
        )

    @property
    def computed_digest(self) -> str:
        """The digest this proposal's contents hash to, regardless of its claim."""
        return digest_of(self.content())

    def to_json(self) -> dict[str, Any]:
        """The whole on-disk record, as JSON-ready data."""
        return self.content() | {"digest": self.digest}

    @classmethod
    def from_json(cls, raw: object) -> Proposal:
        """Decodes and re-checks a stored proposal. Edits are refused, not repaired.

        This door does not resolve citations: it has no run store, and a queue
        must be able to display a proposal whose evidence directory may have
        moved. The evidence was resolved at `build`; what this method proves is
        that the record is exactly the one that was built.
        """
        if not isinstance(raw, Mapping):
            raise ProposalError(
                f"a proposal must be a JSON object, got {type(raw).__name__}"
            )
        unknown = sorted(set(raw) - _RECORD_KEYS)
        if unknown:
            raise ProposalError(f"a proposal has an unknown key {unknown[0]!r}")
        missing = sorted(_RECORD_KEYS - set(raw))
        if missing:
            raise ProposalError(f"a proposal is missing the {missing[0]!r} key")

        schema = raw["schema"]
        if schema != SCHEMA:
            raise ProposalError(
                f"this proposal is schema {schema!r}, but this build reads {SCHEMA!r}. "
                "A record is refused rather than read through new field meanings."
            )

        digest = _require_id(raw["digest"], "proposal digest")
        version_id = _require_id(raw["version_id"], "version id")
        kind = _coerce_kind(raw["kind"])

        parent = raw["parent"]
        if parent is not None:
            parent = _require_id(parent, "version id")

        provenance_raw = raw["provenance"]
        if provenance_raw is None:
            raise ProposalError(
                "a proposal requires provenance, and this record has none. An "
                "anonymous proposal is indistinguishable from one that was never "
                "attributed."
            )
        provenance = Provenance.from_dict(provenance_raw)
        if provenance is None:
            raise ProposalError(
                "the proposal's provenance record is unreadable. Refusing rather "
                "than dropping it: an anonymous proposal would be indistinguishable "
                "from one that was never attributed."
            )

        note = _require_note(raw["note"])

        citations_raw = raw["citations"]
        if not isinstance(citations_raw, list):
            raise ProposalError(
                "a proposal's citations must be a list, got "
                f"{type(citations_raw).__name__}"
            )
        citations = tuple(Citation.from_json(item) for item in citations_raw)

        return cls(
            digest=digest,
            version_id=version_id,
            kind=kind,
            document=raw["document"],
            provenance=provenance,
            note=note,
            parent=parent,
            citations=citations,
            agent_version=raw["agent_version"],
            prompt_version=raw["prompt_version"],
            model_version=raw["model_version"],
        )

    @classmethod
    def build(
        cls,
        *,
        kind: PolicyKind | str,
        document: object,
        provenance: Provenance,
        citations: Sequence[Citation],
        resolver: CitationResolver | None,
        agent_version: str,
        prompt_version: str,
        model_version: str,
        note: str = "",
        parent: str | None = None,
    ) -> Proposal:
        """Validates, resolves and signs one proposal, refusing it before review.

        Order matters. The kind, provenance, versions and document are checked
        before any evidence is resolved, so a malformed rule never reaches the
        resolver; then every citation must resolve to exactly the flow it names.
        Only then are the two ids computed: the store version id from the
        canonical commit, and the proposal digest over the commit, its evidence
        and its producers.
        """
        policy_kind = _coerce_kind(kind)
        record = _require_provenance(provenance)
        note_text = _require_note(note)
        agent = _require_text(agent_version, "agent_version")
        prompt = _require_text(prompt_version, "prompt_version")
        model = _require_text(model_version, "model_version")
        if parent is not None:
            _require_id(parent, "version id")

        normalised = _canonical_document(policy_kind, document)
        ordered = _ordered_citations(citations)

        if resolver is None:
            raise ProposalError(
                "a proposal needs a CitationResolver to resolve its evidence; got "
                "None. Citations are checked before review, not after it."
            )
        for cited in ordered:
            flow = resolver.resolve(cited)
            if flow is None:
                raise ProposalError(
                    f"citation {cited.five_tuple} cannot be resolved in run "
                    f"{cited.run_id}. A citation that points at no stored flow is "
                    "uncheckable, so the proposal is refused before review."
                )
            if flow.five_tuple != cited.five_tuple:
                raise ProposalError(
                    "the resolver returned a different flow for citation "
                    f"{cited.five_tuple} ({flow.five_tuple}). A citation names the "
                    "flow it is evidence about."
                )

        version_id = _version_id(policy_kind, normalised, record, note_text, parent)
        digest = digest_of(
            _content(
                version_id=version_id,
                kind=policy_kind,
                document=normalised,
                provenance=record,
                note=note_text,
                parent=parent,
                citations=ordered,
                agent_version=agent,
                prompt_version=prompt,
                model_version=model,
            )
        )
        return cls(
            digest=digest,
            version_id=version_id,
            kind=policy_kind,
            document=normalised,
            provenance=record,
            note=note_text,
            parent=parent,
            citations=ordered,
            agent_version=agent,
            prompt_version=prompt,
            model_version=model,
        )
