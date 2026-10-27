"""`T6-02` — the signed proposal: validated policy, evidence, and one digest.

**What this file is protecting.** The proposal is the only value that crosses
the human gate, so it has to answer two questions before anyone looks at it:
*is this policy valid?* and *is its evidence checkable?* Both are answered at
`build`, not at `apply`: a malformed document is refused by the same loader the
store uses, and every citation is resolved through the `CitationResolver` port.
A queue that accepted either would turn a malformed change into a human's
problem, and a fabricated citation into reviewable evidence.

**"Signed" means content-bound, not keyed.** The digest covers the canonical
document, the provenance, the note, the parent, the citations and the
agent/prompt/model versions. `from_json` recomputes both that digest and the
`RuleStore` version id the commit would mint, so an edit to any of them is
refused. It does not prove who wrote the proposal; someone who can rewrite the
queue can recompute a digest, and that threat belongs to the append-only audit
chain rather than being pretended away here. Two boundaries are pinned below:
citation order is not content, and the digest does not depend on the mutable
contents of the run a citation points at.

**Why the version id is here as well as the digest.** The digest binds the
review; the version id binds the commit. `apply` will recompute both, so a
proposal whose document was swapped for one the store would file under a
different id is refused even if its reader edited the digest to match.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

import dpi_engine.proposal as proposal_module
from dpi_engine.proposal import (
    SCHEMA,
    Citation,
    CitationResolver,
    Proposal,
    ProposalError,
)
from dpi_engine.rule_manager import Provenance
from dpi_engine.rule_store import PolicyKind, RuleStore, RuleStoreError, digest_of
from dpi_engine.types import FiveTuple, FlowRecord

RUN_ID = "0123456789abcdef"
OTHER_RUN_ID = "fedcba9876543210"
T1 = "2026-10-26T09:00:00+00:00"
T2 = "2026-10-26T09:05:00+00:00"

SRC_IP = 0xCB007109  # 203.0.113.9
DST_IP = 0x5DB8D822  # 93.184.216.34

#: A sentinel so a test can ask for `resolver=None` without `build_proposal`
#: quietly substituting its default.
_UNSET = object()


# ---------------------------------------------------------------------------
# Fixtures and builders
# ---------------------------------------------------------------------------


def empty_ruleset(**overrides: Any) -> dict[str, Any]:
    """A rules document in the shape `RuleManager.to_dict` writes."""
    document: dict[str, Any] = {
        "blocked_ips": [],
        "blocked_apps": [],
        "blocked_cidrs": [],
        "blocked_domains": [],
        "domain_patterns": [],
        "blocked_ports": [],
    }
    document.update(overrides)
    return document


def signature_table(signature_id: str = "sig-zoom") -> dict[str, Any]:
    """A minimal table in the shape `SignatureTable.to_json` writes."""
    return {
        "version": 1,
        "signatures": [
            {
                "id": signature_id,
                "app": "Zoom",
                "all_of": [{"field": "ja3", "value": "abcd"}],
            }
        ],
    }


def provenance(
    author: str = "agent:policy", created_at: str = T1, **overrides: Any
) -> Provenance:
    return Provenance(
        source="agent:policy", author=author, created_at=created_at, **overrides
    )


def flow(
    *,
    src_ip: int = SRC_IP,
    dst_ip: int = DST_IP,
    src_port: int = 50000,
    dst_port: int = 443,
    protocol: int = 6,
    app: str = "UNKNOWN",
    hostname: str = "",
) -> FlowRecord:
    return FlowRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        app=app,
        state="ESTABLISHED",
        hostname=hostname,
        packets=3,
        bytes=120,
    )


def citation(
    flow_record: FlowRecord | None = None, run_id: str = RUN_ID
) -> Citation:
    record = flow() if flow_record is None else flow_record
    return Citation(run_id=run_id, five_tuple=record.five_tuple)


class FakeResolver:
    """The `CitationResolver` port, backed by an in-memory run."""

    def __init__(self, *flows: FlowRecord, run_id: str = RUN_ID) -> None:
        self.run_id = run_id
        self.by_flow = {record.five_tuple: record for record in flows}
        self.asked: list[Citation] = []

    def resolve(self, cited: Citation) -> FlowRecord | None:
        self.asked.append(cited)
        if cited.run_id != self.run_id:
            return None
        return self.by_flow.get(cited.five_tuple)


def build_proposal(
    *,
    resolver: object = _UNSET,
    citations: Sequence[Citation] | None = None,
    **overrides: Any,
) -> Proposal:
    default_flow = flow()
    arguments: dict[str, Any] = {
        "kind": PolicyKind.RULESET,
        "document": empty_ruleset(blocked_ips=["203.0.113.9"]),
        "provenance": provenance(),
        "note": "blocked after review",
        "citations": (citation(default_flow),) if citations is None else citations,
        "resolver": (
            FakeResolver(default_flow) if resolver is _UNSET else resolver
        ),
        "agent_version": "policy-agent/1",
        "prompt_version": "policy-prompt/3",
        "model_version": "model-x/2026-10-01",
    }
    arguments.update(overrides)
    return Proposal.build(**arguments)


# ---------------------------------------------------------------------------
# Round-tripping, and the shape of the record
# ---------------------------------------------------------------------------


def test_a_proposal_round_trips_as_the_commit_it_authorises() -> None:
    proposal = build_proposal()

    assert proposal.kind is PolicyKind.RULESET
    assert proposal.document == empty_ruleset(blocked_ips=["203.0.113.9"])
    assert proposal.provenance == provenance()
    assert proposal.note == "blocked after review"
    assert proposal.parent is None
    assert proposal.citations == (citation(),)
    assert proposal.agent_version == "policy-agent/1"
    assert proposal.prompt_version == "policy-prompt/3"
    assert proposal.model_version == "model-x/2026-10-01"
    assert proposal.digest == proposal.computed_digest

    assert Proposal.from_json(proposal.to_json()) == proposal


def test_a_signature_proposal_round_trips() -> None:
    proposal = build_proposal(kind=PolicyKind.SIGNATURES, document=signature_table())

    assert proposal.kind is PolicyKind.SIGNATURES
    assert proposal.document == signature_table()
    assert Proposal.from_json(proposal.to_json()) == proposal


def test_the_wire_record_has_one_shape() -> None:
    proposal = build_proposal()

    assert proposal.to_json() == {
        "schema": SCHEMA,
        "version_id": proposal.version_id,
        "kind": "ruleset",
        "document": empty_ruleset(blocked_ips=["203.0.113.9"]),
        "provenance": provenance().to_dict(),
        "note": "blocked after review",
        "parent": None,
        "citations": [
            {
                "run_id": RUN_ID,
                "src_ip": SRC_IP,
                "dst_ip": DST_IP,
                "src_port": 50000,
                "dst_port": 443,
                "protocol": 6,
            }
        ],
        "agent_version": "policy-agent/1",
        "prompt_version": "policy-prompt/3",
        "model_version": "model-x/2026-10-01",
        "digest": proposal.digest,
    }


def test_the_record_is_plain_json() -> None:
    proposal = build_proposal()

    encoded = json.dumps(proposal.to_json())

    assert json.loads(encoded) == proposal.to_json()


# ---------------------------------------------------------------------------
# The store id: what `apply` will commit
# ---------------------------------------------------------------------------


def test_the_version_id_is_the_one_the_store_would_mint(tmp_path: Path) -> None:
    proposal = build_proposal()
    store = RuleStore(tmp_path / "policy")

    committed = store.commit(
        proposal.kind,
        proposal.document,
        provenance=proposal.provenance,
        note=proposal.note,
        parent=proposal.parent,
    )

    assert proposal.version_id == committed.version_id
    assert store.load(proposal.version_id) == committed


def test_a_partial_ruleset_is_canonicalised_before_the_id_is_minted(
    tmp_path: Path,
) -> None:
    partial = {"blocked_ips": ["203.0.113.9"]}
    proposal = build_proposal(document=partial)
    store = RuleStore(tmp_path / "policy")

    committed = store.commit(
        PolicyKind.RULESET,
        partial,
        provenance=proposal.provenance,
        note=proposal.note,
    )

    assert set(proposal.document) == set(empty_ruleset())
    assert proposal.version_id == committed.version_id


def test_a_parent_changes_the_version_id_and_round_trips() -> None:
    parent = "0" * 16
    rooted = build_proposal(parent=parent)
    plain = build_proposal()

    assert rooted.parent == parent
    assert rooted.version_id != plain.version_id
    assert Proposal.from_json(rooted.to_json()) == rooted


# ---------------------------------------------------------------------------
# What the digest covers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rebuild",
    [
        lambda: build_proposal(
            document=empty_ruleset(blocked_ips=["203.0.113.10"])
        ),
        lambda: build_proposal(provenance=provenance(author="operator:bob")),
        lambda: build_proposal(provenance=provenance(created_at=T2)),
        lambda: build_proposal(note="a different note"),
        lambda: build_proposal(parent="0" * 16),
        lambda: build_proposal(
            citations=(citation(), citation(flow(src_port=50001))),
            resolver=FakeResolver(flow(), flow(src_port=50001)),
        ),
        lambda: build_proposal(agent_version="policy-agent/2"),
        lambda: build_proposal(prompt_version="policy-prompt/4"),
        lambda: build_proposal(model_version="model-y/2026-10-02"),
    ],
    ids=[
        "document",
        "provenance-author",
        "provenance-time",
        "note",
        "parent",
        "citations",
        "agent-version",
        "prompt-version",
        "model-version",
    ],
)
def test_every_content_field_changes_the_digest(
    rebuild: Callable[[], Proposal],
) -> None:
    assert rebuild().digest != build_proposal().digest


def test_the_store_id_covers_the_policy_and_not_the_review() -> None:
    """Citations and model versions are proposal content, not policy bytes."""
    other = flow(src_port=50001)
    base = build_proposal()
    reviewed = build_proposal(
        citations=(citation(), citation(other)),
        resolver=FakeResolver(flow(), other),
    )

    assert reviewed.digest != base.digest
    assert reviewed.version_id == base.version_id


def test_citation_order_is_not_content() -> None:
    first, second = flow(), flow(src_port=50001)

    one = build_proposal(
        citations=(citation(first), citation(second)),
        resolver=FakeResolver(first, second),
    )
    two = build_proposal(
        citations=(citation(second), citation(first)),
        resolver=FakeResolver(first, second),
    )

    assert one.citations == two.citations
    assert one == two


def test_the_digest_does_not_depend_on_the_resolved_flow() -> None:
    """A citation pins a run and a tuple, not a snapshot of a mutable row.

    The run store is content-addressed and refuses an edited record, so the
    pointer is the stable thing to bind. Freezing the row here would make the
    proposal's identity depend on a decoder's rendering of a feature vector.
    """
    first = flow(app="UNKNOWN")
    second = dataclasses.replace(first, app="Zoom", hostname="zoom.us")

    one = build_proposal(citations=(citation(first),), resolver=FakeResolver(first))
    two = build_proposal(citations=(citation(first),), resolver=FakeResolver(second))

    assert one == two


def test_two_builds_of_the_same_content_are_identical() -> None:
    first = build_proposal()
    second = build_proposal()

    assert first == second
    assert first.digest == second.digest
    assert first.version_id == second.version_id


# ---------------------------------------------------------------------------
# Refusals before review: the document, the provenance, the evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "document", "fragment"),
    [
        (PolicyKind.RULESET, {"blocked_ips": ["not-an-ip"]}, "Invalid IPv4"),
        (PolicyKind.RULESET, {"blocked_ports": ["not-a-port"]}, "port"),
        (PolicyKind.SIGNATURES, {"version": 1}, "signatures"),
        (
            PolicyKind.SIGNATURES,
            signature_table() | {"extra": True},
            "unknown key",
        ),
    ],
)
def test_a_malformed_document_is_refused_by_its_loader(
    kind: PolicyKind, document: object, fragment: str
) -> None:
    resolver = FakeResolver(flow())

    with pytest.raises(ProposalError, match=fragment):
        build_proposal(kind=kind, document=document, resolver=resolver)

    # The document is checked before the evidence is resolved: a malformed
    # proposal never reaches the resolver at all.
    assert resolver.asked == []


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ProposalError, match="JSON object"):
        build_proposal(document=["blocked_ips"])


def test_a_document_that_is_not_json_data_is_refused() -> None:
    """The loader ignores unknown keys, so serialisability is checked separately."""
    raw = build_proposal().to_json()
    raw["document"]["not_a_rule"] = {1, 2}

    with pytest.raises(ProposalError, match="JSON data"):
        Proposal.from_json(raw)


def test_a_missing_provenance_is_refused() -> None:
    with pytest.raises(ProposalError, match="requires provenance"):
        build_proposal(provenance=None)


def test_a_provenance_of_the_wrong_type_is_refused() -> None:
    with pytest.raises(ProposalError, match="requires provenance"):
        build_proposal(provenance={"source": "agent:policy"})


def test_a_proposal_that_cites_nothing_is_refused() -> None:
    with pytest.raises(ProposalError, match="cite"):
        build_proposal(citations=())


def test_a_proposal_with_a_non_citation_in_its_evidence_is_refused() -> None:
    with pytest.raises(ProposalError, match="Citation"):
        build_proposal(citations=("not a citation",))


def test_a_duplicate_citation_is_refused() -> None:
    with pytest.raises(ProposalError, match="twice"):
        build_proposal(citations=(citation(), citation()))


def test_an_unresolvable_citation_is_refused_before_review() -> None:
    resolver = FakeResolver()  # the run holds no flows

    with pytest.raises(ProposalError, match="cannot be resolved"):
        build_proposal(citations=(citation(),), resolver=resolver)

    assert resolver.asked == [citation()]


def test_a_citation_from_another_run_is_unresolvable() -> None:
    with pytest.raises(ProposalError, match="cannot be resolved"):
        build_proposal(citations=(citation(run_id=OTHER_RUN_ID),))


def test_a_resolver_that_returns_another_flow_is_refused() -> None:
    class WrongResolver:
        def resolve(self, cited: Citation) -> FlowRecord | None:
            return flow(src_port=1)

    with pytest.raises(ProposalError, match="different flow"):
        build_proposal(resolver=WrongResolver())


def test_a_missing_resolver_is_refused() -> None:
    with pytest.raises(ProposalError, match="CitationResolver"):
        build_proposal(resolver=None)


def test_a_citation_list_that_is_not_a_sequence_is_refused() -> None:
    with pytest.raises(ProposalError, match="must be a list"):
        build_proposal(citations="0123456789abcdef")


def test_an_unknown_policy_kind_of_another_type_is_refused() -> None:
    with pytest.raises(ProposalError, match="unknown policy kind"):
        build_proposal(kind=7)


def test_a_store_refusal_while_minting_the_id_is_a_proposal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module's door raises `ProposalError`, whatever the store said."""

    def refuse(*args: object, **kwargs: object) -> str:
        raise RuleStoreError("the store refused this commit")

    monkeypatch.setattr(proposal_module, "version_id_for", refuse)

    with pytest.raises(ProposalError, match="the store refused this commit"):
        build_proposal()


def test_an_unknown_policy_kind_is_refused() -> None:
    with pytest.raises(ProposalError, match="unknown policy kind"):
        build_proposal(kind="rules")


def test_a_non_string_note_is_refused() -> None:
    with pytest.raises(ProposalError, match="note"):
        build_proposal(note=7)


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("version_field", ["agent_version", "prompt_version", "model_version"])
def test_an_empty_version_string_is_refused(version_field: str, blank: str) -> None:
    with pytest.raises(ProposalError, match=version_field):
        build_proposal(**{version_field: blank})


@pytest.mark.parametrize("parent", ["nope", "0" * 15, "ABCDEF0123456789"])
def test_a_parent_that_is_not_an_id_is_refused(parent: str) -> None:
    with pytest.raises(ProposalError, match="version id"):
        build_proposal(parent=parent)


def test_a_decoded_proposal_does_not_alias_the_record_it_was_decoded_from() -> None:
    """A decoded proposal is a value, not a view onto the queue's dictionary."""
    raw = build_proposal().to_json()
    proposal = Proposal.from_json(raw)

    raw["document"]["blocked_ips"].append("198.51.100.7")

    assert proposal.document == empty_ruleset(blocked_ips=["203.0.113.9"])
    assert proposal.digest == proposal.computed_digest


def test_a_directly_constructed_proposal_does_not_alias_its_document() -> None:
    """A frozen proposal holds its own document; the caller's dict cannot edit it."""
    document = empty_ruleset(blocked_ips=["203.0.113.9"])
    proposal = dataclasses.replace(build_proposal(), document=document)

    document["blocked_ips"].append("198.51.100.7")

    assert proposal.document == empty_ruleset(blocked_ips=["203.0.113.9"])
    assert proposal.digest == proposal.computed_digest


# ---------------------------------------------------------------------------
# Citations: the codec and its own refusals
# ---------------------------------------------------------------------------


def test_a_citation_flattens_to_a_query_row_plus_a_run() -> None:
    assert citation().to_json() == {
        "run_id": RUN_ID,
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 6,
    }


def test_a_citation_round_trips() -> None:
    assert Citation.from_json(citation().to_json()) == citation()


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"run_id": "nope"}, "run id"),
        ({"run_id": OTHER_RUN_ID[:-1] + "g"}, "run id"),
        ({"run_id": 7}, "run id"),
        ({"five_tuple": (1, 2, 3, 4, 5)}, "FiveTuple"),
    ],
)
def test_a_citation_with_a_bad_key_is_refused(
    kwargs: dict[str, Any], fragment: str
) -> None:
    fields: dict[str, Any] = {
        "run_id": RUN_ID,
        "five_tuple": flow().five_tuple,
    } | kwargs

    with pytest.raises(ProposalError, match=fragment):
        Citation(**fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("src_ip", -1),
        ("src_ip", 2**32),
        ("dst_ip", -1),
        ("src_port", 65536),
        ("dst_port", -1),
        ("protocol", 256),
        ("src_port", True),
    ],
)
def test_a_citation_flow_field_outside_its_range_is_refused(
    field: str, value: object
) -> None:
    parts = flow().five_tuple._asdict()
    parts[field] = value

    with pytest.raises(ProposalError, match=field):
        Citation(run_id=RUN_ID, five_tuple=FiveTuple(**parts))


@pytest.mark.parametrize(
    ("raw", "fragment"),
    [
        ([], "JSON object"),
        ({"run_id": RUN_ID}, "missing"),
        ({"run_id": RUN_ID, "extra": 1}, "unknown"),
        (citation().to_json() | {"src_port": "443"}, "integer"),
        (citation().to_json() | {"protocol": True}, "integer"),
        (citation().to_json() | {"run_id": "nope"}, "run id"),
        (citation().to_json() | {"run_id": 7}, "must be a string"),
    ],
)
def test_a_citation_record_is_checked(raw: object, fragment: str) -> None:
    with pytest.raises(ProposalError, match=fragment):
        Citation.from_json(raw)


# ---------------------------------------------------------------------------
# An edited proposal is refused
# ---------------------------------------------------------------------------


def test_an_edited_document_is_refused() -> None:
    raw = build_proposal().to_json()
    raw["document"]["blocked_ips"] = ["198.51.100.7"]

    with pytest.raises(ProposalError, match="not the version its contents would mint"):
        Proposal.from_json(raw)


def test_edited_provenance_is_refused() -> None:
    raw = build_proposal().to_json()
    raw["provenance"]["author"] = "operator:mallory"

    with pytest.raises(ProposalError, match="not the version its contents would mint"):
        Proposal.from_json(raw)


def test_edited_citations_are_refused() -> None:
    raw = build_proposal().to_json()
    raw["citations"][0]["src_port"] = 50001

    with pytest.raises(ProposalError, match="does not match its contents"):
        Proposal.from_json(raw)


def test_an_edited_parent_is_refused() -> None:
    raw = build_proposal().to_json() | {"parent": "0" * 16}

    with pytest.raises(ProposalError, match="not the version its contents would mint"):
        Proposal.from_json(raw)


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        # Bound by the version id: these change the commit the store would mint.
        ({"version_id": "0" * 16}, "not the version its contents would mint"),
        ({"note": "rewritten"}, "not the version its contents would mint"),
        # Bound only by the digest: the policy bytes are unchanged.
        ({"digest": "0" * 16}, "does not match its contents"),
        ({"agent_version": "policy-agent/9"}, "does not match its contents"),
        ({"prompt_version": "policy-prompt/9"}, "does not match its contents"),
        ({"model_version": "model-z/9"}, "does not match its contents"),
    ],
)
def test_edited_metadata_is_refused(change: dict[str, Any], fragment: str) -> None:
    raw = build_proposal().to_json() | change

    with pytest.raises(ProposalError, match=fragment):
        Proposal.from_json(raw)


def test_a_non_canonical_document_is_refused_even_with_a_recomputed_digest() -> None:
    """The digest binds the bytes; canonicality is a second, independent invariant.

    This is the check that catches an editor who recomputes the digest over the
    edited record: the version id still matches, because the loader strips the
    live `version` counter, but the document is not the one `build` stores.
    """
    raw = build_proposal().to_json()
    raw["document"]["version"] = 5
    content = {key: value for key, value in raw.items() if key != "digest"}
    raw["digest"] = digest_of(content)

    with pytest.raises(ProposalError, match="canonical"):
        Proposal.from_json(raw)


# ---------------------------------------------------------------------------
# The record codec, directly
# ---------------------------------------------------------------------------


def test_a_record_with_an_unknown_field_is_refused() -> None:
    raw = build_proposal().to_json() | {"unexpected": True}

    with pytest.raises(ProposalError, match="unknown"):
        Proposal.from_json(raw)


def test_a_record_with_a_missing_field_is_refused() -> None:
    raw = build_proposal().to_json()
    del raw["citations"]

    with pytest.raises(ProposalError, match="missing"):
        Proposal.from_json(raw)


def test_a_record_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ProposalError, match="JSON object"):
        Proposal.from_json([])


def test_citations_that_are_not_a_list_are_refused() -> None:
    raw = build_proposal().to_json() | {"citations": citation().to_json()}

    with pytest.raises(ProposalError, match="list"):
        Proposal.from_json(raw)


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("schema", "dpi-engine-proposal/v2", "schema"),
        ("digest", "not-an-id", "digest"),
        ("version_id", "not-an-id", "version id"),
        ("kind", "rules", "unknown policy kind"),
        ("parent", "not-an-id", "version id"),
        ("document", [], "JSON object"),
        ("provenance", None, "provenance"),
        ("provenance", {"source": "", "author": ""}, "provenance"),
        ("note", 7, "note"),
        ("citations", [], "cite"),
        (
            "citations",
            [citation().to_json(), citation().to_json()],
            "twice",
        ),
        ("agent_version", "", "agent_version"),
        ("prompt_version", "", "prompt_version"),
        ("model_version", "", "model_version"),
    ],
)
def test_a_record_with_a_bad_field_is_refused(
    field: str, value: object, fragment: str
) -> None:
    raw = build_proposal().to_json() | {field: value}

    with pytest.raises(ProposalError, match=fragment):
        Proposal.from_json(raw)


# ---------------------------------------------------------------------------
# Every Proposal is internally consistent, however it was constructed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"digest": "nope"}, "digest"),
        ({"digest": "0" * 16}, "does not match its contents"),
        ({"version_id": "nope"}, "version id"),
        ({"version_id": "0" * 16}, "not the version its contents would mint"),
        ({"kind": PolicyKind.SIGNATURES}, "not valid"),
        ({"kind": "rules"}, "unknown policy kind"),
        ({"document": []}, "JSON object"),
        ({"provenance": None}, "provenance"),
        ({"note": 7}, "note"),
        ({"citations": ()}, "cite"),
        ({"agent_version": ""}, "agent_version"),
        ({"parent": "nope"}, "version id"),
    ],
)
def test_a_directly_constructed_proposal_is_checked(
    overrides: dict[str, Any], fragment: str
) -> None:
    with pytest.raises(ProposalError, match=fragment):
        dataclasses.replace(build_proposal(), **overrides)


def test_the_resolver_port_is_structural() -> None:
    resolver: CitationResolver = FakeResolver(flow())

    assert build_proposal(resolver=resolver).citations == (citation(),)
