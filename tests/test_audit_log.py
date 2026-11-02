"""The immutable audit log (`T6-06`): an append-only chain a reader can check.

The gate is four sentences:

1. **One append per applied change.** The log is written by the apply door and by
   nothing else; an entry names the proposal, the version, the tier and the human
   (or the engine) that caused it.
2. **It names who, when, which agent, which run, which evidence, which prompt and
   which model.** Those are fields, not prose: a reader can answer each question
   without parsing a sentence.
3. **Append-only with a hash chain.** Each entry's hash covers the previous hash,
   so editing an entry breaks it and deleting one breaks the next.
4. **`verify_chain` is the reader.** It refuses an edited entry, a deleted middle
   entry, a deleted *last* entry (the head anchor catches that), a reordered
   entry, an unknown key and a foreign schema.

The honest limit is named here too: a hash chain cannot detect truncation of the
whole log together with its head file, because there is nothing outside the
directory to compare against. An external anchor is a deployment concern, not a
file format.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from dpi_engine import audit_log as audit_module
from dpi_engine.audit_log import (
    AUTO_ACTOR,
    GENESIS_HASH,
    SCHEMA,
    AuditLog,
    AuditLogError,
    AuditRecord,
)
from dpi_engine.blast_radius import Tier, classify
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_manager import Provenance
from dpi_engine.rule_store import PolicyKind, RuleStore, RuleStoreError, canonical_json
from dpi_engine.rules.simulator import SimulationReport
from dpi_engine.types import FiveTuple, FlowRecord

RUN_ID = "0123456789abcdef"
NOW = "2026-11-01T09:00:00+00:00"
LATER = "2026-11-01T10:30:00+00:00"
REVIEWER = "on-call-1"

_FLOW = FiveTuple(
    src_ip=0x0A000001,
    dst_ip=0x0A000002,
    src_port=49152,
    dst_port=443,
    protocol=6,
)
_RECORD = FlowRecord(
    src_ip=_FLOW.src_ip,
    dst_ip=_FLOW.dst_ip,
    src_port=_FLOW.src_port,
    dst_port=_FLOW.dst_port,
    protocol=_FLOW.protocol,
    app="TIKTOK",
    state="ESTABLISHED",
    packets=3,
    bytes=120,
)
_RULESET = {"blocked_apps": ["TIKTOK"]}
_SIGNATURES = {
    "version": 1,
    "signatures": [
        {"id": "sig-zoom", "app": "Zoom", "all_of": [{"field": "ja3", "value": "abcd"}]}
    ],
}


class _Resolver:
    def resolve(self, cited: Citation) -> FlowRecord | None:
        if cited.run_id == RUN_ID and cited.five_tuple == _FLOW:
            return _RECORD
        return None


def _proposal(
    *,
    document: dict[str, Any] | None = None,
    kind: PolicyKind = PolicyKind.RULESET,
    note: str = "blocked after review",
) -> Proposal:
    default_document = _SIGNATURES if kind is PolicyKind.SIGNATURES else _RULESET
    return Proposal.build(
        kind=kind,
        document=default_document if document is None else document,
        provenance=Provenance(
            source="agent:policy",
            author="policy-agent/1",
            evidence=f"run {RUN_ID}",
            created_at=NOW,
        ),
        note=note,
        citations=(Citation(run_id=RUN_ID, five_tuple=_FLOW),),
        resolver=_Resolver(),
        agent_version="policy-agent/1",
        prompt_version="policy/1",
        model_version="model-x/2026-11-01",
    )


def _decision(proposal: Proposal | None = None) -> Any:
    report = SimulationReport(
        newly_blocked=(),
        newly_allowed=(),
        unchanged_blocked=(),
        baseline_blocked=0,
        candidate_blocked=0,
        baseline_dropped=0,
        candidate_dropped=0,
        baseline_forwarded=77,
        candidate_forwarded=77,
        baseline_total_packets=77,
        candidate_total_packets=77,
        drop_rate_change_percent=0.0,
        total_loss=False,
        baseline_output=Path("baseline_sim.pcap"),
        candidate_output=Path("candidate_sim.pcap"),
    )
    return classify(_proposal() if proposal is None else proposal, report)


def _version(
    store: RuleStore, proposal: Proposal, *, note: str | None = None
) -> Any:
    return store.commit(
        proposal.kind,
        proposal.document,
        provenance=proposal.provenance,
        note=proposal.note if note is None else note,
        parent=proposal.parent,
    )


def _log(tmp_path: Path, *times: str) -> AuditLog:
    remaining = list(times) or [NOW]
    ticks = iter(remaining)
    return AuditLog(tmp_path, clock=lambda: next(ticks, remaining[-1]))


def _append(
    log: AuditLog,
    store: RuleStore,
    proposal: Proposal | None = None,
    *,
    tier: Tier = Tier.ONE_CLICK,
    actor: str = REVIEWER,
    request_id: str | None = None,
) -> AuditRecord:
    chosen = _proposal() if proposal is None else proposal
    if tier is Tier.AUTO_APPLY:
        request_id = None
    elif request_id is None:
        request_id = "fedcba9876543210"
    return log.append(
        proposal=chosen,
        version=_version(store, chosen),
        tier=tier,
        actor=actor,
        request_id=request_id,
    )


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _rewrite_lines(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _rehash(raw: dict[str, Any]) -> dict[str, Any]:
    """Recompute an entry's hash, so a test can forge a *consistent* bad link."""
    content = {key: value for key, value in raw.items() if key != "hash"}
    raw["hash"] = hashlib.sha256(
        canonical_json(content).encode("utf-8")
    ).hexdigest()
    return raw


# ---------------------------------------------------------------------------
# One record: the fields the gate names
# ---------------------------------------------------------------------------


class TestTheRecord:
    def test_a_record_names_who_when_which_agent_run_evidence_and_versions(
        self, tmp_path: Path
    ) -> None:
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()

        record = _append(_log(tmp_path / "audit"), store, proposal)

        assert record.actor == REVIEWER
        assert record.applied_at == NOW
        assert record.tier is Tier.ONE_CLICK
        assert record.request_id == "fedcba9876543210"
        assert record.proposal_digest == proposal.digest
        assert record.version_id == _version(store, proposal).version_id
        assert record.kind is PolicyKind.RULESET
        assert record.agent_version == "policy-agent/1"
        assert record.prompt_version == "policy/1"
        assert record.model_version == "model-x/2026-11-01"
        assert record.runs == (RUN_ID,)
        assert record.citations == proposal.citations

    def test_the_auto_apply_record_names_the_engine_not_a_person(
        self, tmp_path: Path
    ) -> None:
        store = RuleStore(tmp_path / "store")

        record = _append(
            _log(tmp_path / "audit"),
            store,
            _proposal(kind=PolicyKind.SIGNATURES),
            tier=Tier.AUTO_APPLY,
            actor=AUTO_ACTOR,
        )

        assert record.actor == AUTO_ACTOR
        assert record.tier is Tier.AUTO_APPLY
        assert record.request_id is None

    def test_a_record_round_trips_through_its_line(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        record = _append(_log(tmp_path / "audit"), store)

        again = AuditRecord.from_json(record.to_json())

        assert again == record
        assert again.hash == record.hash

    def test_the_first_hash_chains_to_genesis(self, tmp_path: Path) -> None:
        record = _append(_log(tmp_path / "audit"), RuleStore(tmp_path / "store"))

        assert record.sequence == 0
        assert record.prev_hash == GENESIS_HASH == "0" * 64
        assert len(record.hash) == 64

    def test_the_second_hash_chains_to_the_first(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit", NOW, LATER)
        store = RuleStore(tmp_path / "store")

        first = _append(log, store)
        second = _append(log, store, _proposal(note="a second change"))

        assert second.sequence == 1
        assert second.prev_hash == first.hash
        assert second.hash != first.hash
        assert first.prev_hash == GENESIS_HASH

    def test_the_hash_covers_every_field(self, tmp_path: Path) -> None:
        """Recompute it by hand: the hash is the canonical content, nothing else."""
        store = RuleStore(tmp_path / "store")
        record = _append(_log(tmp_path / "audit"), store)

        expected = hashlib.sha256(
            canonical_json(record.content()).encode("utf-8")
        ).hexdigest()

        assert record.hash == expected == record.computed_hash
        assert "hash" not in record.content()

    def test_a_record_is_frozen(self, tmp_path: Path) -> None:
        record = _append(_log(tmp_path / "audit"), RuleStore(tmp_path / "store"))

        with pytest.raises(dataclasses.FrozenInstanceError):
            record.actor = "someone-else"  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("sequence", -1, "sequence"),
            ("sequence", True, "sequence"),
            ("prev_hash", "0" * 63, "prev_hash"),
            ("prev_hash", "A" * 64, "prev_hash"),
            ("applied_at", "", "applied_at"),
            ("actor", "   ", "actor"),
            ("tier", "one_click", "tier"),
            ("request_id", "fedcba", "request_id"),
            ("proposal_digest", "0" * 15, "proposal_digest"),
            ("version_id", "0" * 17, "version_id"),
            ("kind", "rule-set", "kind"),
            ("agent_version", "", "agent_version"),
            ("prompt_version", "", "prompt_version"),
            ("model_version", "", "model_version"),
            ("citations", (), "citations"),
            ("hash", "0" * 63, "hash must be 64"),
        ],
    )
    def test_a_record_refuses_a_bad_field(
        self, tmp_path: Path, field: str, value: Any, message: str
    ) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw[field] = value

        with pytest.raises(AuditLogError, match=message):
            AuditRecord.from_json(raw)

    def test_an_auto_apply_record_without_a_request_id_is_required(
        self, tmp_path: Path
    ) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(
            _log(tmp_path / "audit"),
            store,
            _proposal(kind=PolicyKind.SIGNATURES),
            tier=Tier.AUTO_APPLY,
            actor=AUTO_ACTOR,
        ).to_json()
        raw["request_id"] = "fedcba9876543210"

        with pytest.raises(AuditLogError, match="request_id"):
            AuditRecord.from_json(raw)

    def test_a_human_tier_without_a_request_id_is_refused(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["request_id"] = None

        with pytest.raises(AuditLogError, match="request_id"):
            AuditRecord.from_json(raw)

    def test_a_refused_tier_is_never_recorded(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["tier"] = Tier.REFUSED.value
        raw["request_id"] = None

        with pytest.raises(AuditLogError, match="refused"):
            AuditRecord.from_json(raw)

    def test_an_edited_record_is_refused_by_its_hash(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["actor"] = "someone-else"

        with pytest.raises(AuditLogError, match="hash"):
            AuditRecord.from_json(raw)

    def test_an_edited_prev_hash_is_refused_by_its_hash(self, tmp_path: Path) -> None:
        """The link is part of the hashed content, not a field beside it."""
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["prev_hash"] = "a" * 64

        with pytest.raises(AuditLogError, match="hash"):
            AuditRecord.from_json(raw)

    def test_a_record_refuses_unknown_and_missing_keys(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()

        with pytest.raises(AuditLogError, match="unknown key"):
            AuditRecord.from_json(raw | {"approved": True})
        with pytest.raises(AuditLogError, match="missing"):
            AuditRecord.from_json(
                {key: value for key, value in raw.items() if key != "actor"}
            )

    def test_a_foreign_schema_is_refused(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["schema"] = "dpi-engine-audit/v2"

        with pytest.raises(AuditLogError, match="schema"):
            AuditRecord.from_json(raw)

    def test_a_record_must_be_a_json_object(self) -> None:
        with pytest.raises(AuditLogError, match="JSON object"):
            AuditRecord.from_json(["not", "an", "object"])

    def test_a_directly_constructed_record_checks_its_enum_fields(
        self, tmp_path: Path
    ) -> None:
        record = _append(_log(tmp_path / "audit"), RuleStore(tmp_path / "store"))

        with pytest.raises(AuditLogError, match="tier"):
            dataclasses.replace(record, tier="one-click")
        with pytest.raises(AuditLogError, match="kind"):
            dataclasses.replace(record, kind="ruleset")

    def test_a_directly_constructed_record_checks_its_citations(
        self, tmp_path: Path
    ) -> None:
        record = _append(_log(tmp_path / "audit"), RuleStore(tmp_path / "store"))

        with pytest.raises(AuditLogError, match="citations"):
            dataclasses.replace(record, citations=())
        with pytest.raises(AuditLogError, match="Citation"):
            dataclasses.replace(record, citations=(_FLOW,))

    def test_an_empty_citation_list_is_refused(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["citations"] = []

        with pytest.raises(AuditLogError, match="citations"):
            AuditRecord.from_json(raw)

    def test_an_auto_entry_must_name_the_engine(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["tier"] = Tier.AUTO_APPLY.value
        raw["request_id"] = None
        raw["actor"] = REVIEWER

        with pytest.raises(AuditLogError, match="actor"):
            AuditRecord.from_json(raw)

    def test_an_auto_entry_must_be_a_signatures_version(self, tmp_path: Path) -> None:
        store = RuleStore(tmp_path / "store")
        raw = _append(_log(tmp_path / "audit"), store).to_json()
        raw["tier"] = Tier.AUTO_APPLY.value
        raw["request_id"] = None
        raw["actor"] = AUTO_ACTOR

        with pytest.raises(AuditLogError, match="signature"):
            AuditRecord.from_json(raw)


# ---------------------------------------------------------------------------
# Appending: one line, then the head anchor
# ---------------------------------------------------------------------------


class TestAppending:
    def test_append_writes_one_line_and_a_head_file(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        record = _append(log, RuleStore(tmp_path / "store"))

        lines = log.path.read_text(encoding="utf-8").splitlines()
        head = json.loads(log.head_path.read_text(encoding="utf-8"))

        assert len(lines) == 1
        assert json.loads(lines[0])["hash"] == record.hash
        assert head == {"schema": SCHEMA, "count": 1, "last_hash": record.hash}

    def test_the_head_is_rewritten_atomically_after_each_append(
        self, tmp_path: Path
    ) -> None:
        log = _log(tmp_path / "audit", NOW, LATER)
        store = RuleStore(tmp_path / "store")
        _append(log, store)
        second = _append(log, store, _proposal(note="another"))

        head = json.loads(log.head_path.read_text(encoding="utf-8"))

        assert head["count"] == 2
        assert head["last_hash"] == second.hash
        assert not list((tmp_path / "audit").glob("*.tmp"))

    def test_the_log_survives_a_new_reader_over_the_same_root(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "audit"
        first = _append(_log(path), RuleStore(tmp_path / "store"))

        records = AuditLog(path).verify_chain()

        assert records == (first,)

    def test_an_empty_log_verifies(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit")

        assert log.verify_chain() == ()
        assert log.applied_digests() == frozenset()

    def test_append_refuses_a_sig_key_and_never_writes_it(
        self, tmp_path: Path
    ) -> None:
        """A rejected candidate must not be in the record of what was applied."""
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal(kind=PolicyKind.SIGNATURES)

        with pytest.raises(AuditLogError, match="refused"):
            log.append(
                proposal=proposal,
                version=_version(store, proposal),
                tier=Tier.REFUSED,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

        assert not log.path.exists()

    def test_append_refuses_a_human_tier_with_no_request(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()

        with pytest.raises(AuditLogError, match="request_id"):
            log.append(
                proposal=proposal,
                version=_version(store, proposal),
                tier=Tier.EXPLICIT_CONFIRM,
                actor=REVIEWER,
            )

    def test_append_refuses_an_auto_apply_with_a_request(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal(kind=PolicyKind.SIGNATURES)

        with pytest.raises(AuditLogError, match="request_id"):
            log.append(
                proposal=proposal,
                version=_version(store, proposal),
                tier=Tier.AUTO_APPLY,
                actor=AUTO_ACTOR,
                request_id="fedcba9876543210",
            )

    def test_append_refuses_a_blank_actor(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")

        with pytest.raises(AuditLogError, match="actor"):
            _append(log, store, actor="   ")

    def test_append_refuses_a_version_of_another_kind(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()
        other = _proposal(kind=PolicyKind.SIGNATURES)

        with pytest.raises(AuditLogError, match="kind"):
            log.append(
                proposal=proposal,
                version=_version(store, other),
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

    def test_append_refuses_a_version_of_another_parent(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        first = _version(store, _proposal())
        proposal = _proposal(note="a child")
        elsewhere = store.commit(
            proposal.kind,
            proposal.document,
            provenance=proposal.provenance,
            note=proposal.note,
            parent=first.version_id,
        )

        assert elsewhere.parent == first.version_id
        assert elsewhere.parent != proposal.parent
        with pytest.raises(AuditLogError, match="parent"):
            log.append(
                proposal=proposal,
                version=elsewhere,
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

    def test_append_refuses_a_version_of_another_id(self, tmp_path: Path) -> None:
        """Same kind, same parent, different bytes: still not this proposal."""
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()

        with pytest.raises(AuditLogError, match="version"):
            log.append(
                proposal=proposal,
                version=_version(store, proposal, note="a different note"),
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

    def test_append_refuses_an_auto_applied_ruleset(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()

        with pytest.raises(AuditLogError, match="signature"):
            log.append(
                proposal=proposal,
                version=_version(store, proposal),
                tier=Tier.AUTO_APPLY,
                actor=AUTO_ACTOR,
            )

    def test_append_refuses_the_wrong_kind_of_argument(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()
        version = _version(store, proposal)

        with pytest.raises(AuditLogError, match="Proposal"):
            log.append(
                proposal="not a proposal",  # type: ignore[arg-type]
                version=version,
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )
        with pytest.raises(AuditLogError, match="PolicyVersion"):
            log.append(
                proposal=proposal,
                version="not a version",  # type: ignore[arg-type]
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )
        with pytest.raises(AuditLogError, match="Tier"):
            log.append(
                proposal=proposal,
                version=version,
                tier="one-click",  # type: ignore[arg-type]
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

    def test_a_log_without_a_clock_stamps_the_entry(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")

        record = _append(log, store)

        assert isinstance(record.applied_at, str)
        assert record.applied_at
        assert AuditLog(log.root).verify_chain() == (record,)

    def test_the_root_is_the_directory_it_was_given(self, tmp_path: Path) -> None:
        root = tmp_path / "audit"

        assert AuditLog(root).root == root

    def test_a_failed_line_write_is_an_audit_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")
        proposal = _proposal()
        version = _version(store, proposal)

        def boom(fd: int) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(audit_module.os, "fsync", boom)
        with pytest.raises(AuditLogError, match="cannot append"):
            log.append(
                proposal=proposal,
                version=version,
                tier=Tier.ONE_CLICK,
                actor=REVIEWER,
                request_id="fedcba9876543210",
            )

    def test_a_failed_head_write_leaves_a_repairable_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A crash between the line and the anchor is exactly what rebuild is for."""
        log = _log(tmp_path / "audit")
        store = RuleStore(tmp_path / "store")

        def boom(*args: Any, **kwargs: Any) -> None:
            raise RuleStoreError("the anchor directory is read-only")

        monkeypatch.setattr(audit_module, "write_json_atomic", boom)
        with pytest.raises(AuditLogError, match="head anchor"):
            _append(log, store)

        assert len(_lines(log.path)) == 1
        with pytest.raises(AuditLogError, match="head"):
            log.verify_chain()

        monkeypatch.undo()
        rebuilt = log.rebuild_head()

        assert rebuilt is not None
        assert log.verify_chain() == (rebuilt,)


# ---------------------------------------------------------------------------
# Verifying: edited, deleted, reordered, foreign
# ---------------------------------------------------------------------------


class TestVerifying:
    def _three(self, tmp_path: Path) -> tuple[AuditLog, list[dict[str, Any]]]:
        log = _log(tmp_path / "audit", NOW, NOW, NOW)
        store = RuleStore(tmp_path / "store")
        _append(log, store)
        _append(log, store, _proposal(note="second"))
        _append(log, store, _proposal(note="third"))
        return log, _lines(log.path)

    def test_three_good_entries_verify_in_order(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)

        records = log.verify_chain()

        assert [record.sequence for record in records] == [0, 1, 2]
        assert records[1].prev_hash == records[0].hash
        assert records[2].prev_hash == records[1].hash

    def test_an_edited_actor_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        records[1]["actor"] = "someone-else"
        _rewrite_lines(log.path, records)

        with pytest.raises(AuditLogError, match="hash"):
            log.verify_chain()

    def test_an_edited_hash_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        records[1]["hash"] = "f" * 64
        _rewrite_lines(log.path, records)

        with pytest.raises(AuditLogError, match="hash"):
            log.verify_chain()

    def test_a_deleted_middle_entry_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        _rewrite_lines(log.path, [records[0], records[2]])

        with pytest.raises(AuditLogError, match=r"contiguous|chains to"):
            log.verify_chain()

    def test_a_deleted_last_entry_is_detected_by_the_head(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        _rewrite_lines(log.path, records[:2])

        with pytest.raises(AuditLogError, match=r"head anchor .* says"):
            log.verify_chain()

    def test_a_reordered_log_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        _rewrite_lines(log.path, [records[1], records[0], records[2]])

        with pytest.raises(AuditLogError, match=r"contiguous|chains to"):
            log.verify_chain()

    def test_a_truncated_line_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        text = log.path.read_text(encoding="utf-8")
        log.path.write_text(text[: len(text) // 2], encoding="utf-8")

        with pytest.raises(AuditLogError, match=r"does not end with a newline|not valid JSON"):
            log.verify_chain()

    def test_a_complete_last_line_without_a_newline_is_detected(
        self, tmp_path: Path
    ) -> None:
        log, _ = self._three(tmp_path)
        text = log.path.read_text(encoding="utf-8").rstrip("\n")
        log.path.write_text(text, encoding="utf-8")

        with pytest.raises(AuditLogError, match="does not end with a newline"):
            log.verify_chain()

    def test_a_gap_in_the_sequence_is_detected(self, tmp_path: Path) -> None:
        """A rehashed entry with the right link and the wrong number is still a gap."""
        log, records = self._three(tmp_path)
        forged = _rehash(records[1] | {"sequence": 5})
        _rewrite_lines(log.path, [records[0], forged, records[2]])

        with pytest.raises(AuditLogError, match="contiguous"):
            log.verify_chain()

    def test_a_blank_line_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        log.path.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n\n",
            encoding="utf-8",
        )

        with pytest.raises(AuditLogError, match="blank line"):
            log.verify_chain()

    def test_a_foreign_schema_in_the_log_is_detected(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        records[2]["schema"] = "other/v1"
        _rewrite_lines(log.path, records)

        with pytest.raises(AuditLogError, match=r"is schema 'other/v1'"):
            log.verify_chain()

    def test_a_missing_head_for_a_non_empty_log_is_detected(
        self, tmp_path: Path
    ) -> None:
        log, _ = self._three(tmp_path)
        log.head_path.unlink()

        with pytest.raises(AuditLogError, match=r"head anchor .* is missing"):
            log.verify_chain()

    def test_a_head_ahead_of_the_log_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["count"] = 4
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match=r"head anchor .* says"):
            log.verify_chain()

    def test_a_head_naming_another_hash_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["last_hash"] = "a" * 64
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match=r"head anchor .* says"):
            log.verify_chain()

    def test_append_refuses_a_log_that_is_already_broken(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        records[1]["actor"] = "someone-else"
        _rewrite_lines(log.path, records)
        store = RuleStore(tmp_path / "store")

        with pytest.raises(AuditLogError, match="hash"):
            _append(log, store, _proposal(note="fourth"))

        assert len(_lines(log.path)) == 3

    def test_rebuild_head_restores_a_torn_append(self, tmp_path: Path) -> None:
        """A crash between the line and the head leaves a repairable log."""
        log, records = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["count"] = 2
        head["last_hash"] = records[1]["hash"]
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match=r"head anchor .* says"):
            log.verify_chain()

        rebuilt = log.rebuild_head()

        assert rebuilt == (logs := log.verify_chain())[-1]
        assert len(logs) == 3
        assert json.loads(log.head_path.read_text(encoding="utf-8"))["count"] == 3

    def test_rebuild_head_refuses_an_edited_log(self, tmp_path: Path) -> None:
        log, records = self._three(tmp_path)
        records[0]["actor"] = "someone-else"
        _rewrite_lines(log.path, records)

        with pytest.raises(AuditLogError, match="hash"):
            log.rebuild_head()

    def test_applied_digests_lists_what_was_applied(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit", NOW, NOW)
        store = RuleStore(tmp_path / "store")
        first = _proposal()
        second = _proposal(note="second")
        _append(log, store, first)
        _append(log, store, second)

        assert log.applied_digests() == {first.digest, second.digest}

    def test_the_head_is_not_the_log(self, tmp_path: Path) -> None:
        """The anchor is a separate file: a reader cannot mistake it for a record."""
        log = _log(tmp_path / "audit")
        record = _append(log, RuleStore(tmp_path / "store"))

        assert log.path != log.head_path
        assert record.hash in log.path.read_text(encoding="utf-8")
        assert record.hash in log.head_path.read_text(encoding="utf-8")

    def test_the_head_file_is_validated(self, tmp_path: Path) -> None:
        log = _log(tmp_path / "audit")
        _append(log, RuleStore(tmp_path / "store"))
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["schema"] = "other/v1"
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match="schema"):
            log.verify_chain()

    def test_a_missing_head_with_an_empty_log_is_fine(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "nowhere")

        assert log.verify_chain() == ()

    def test_an_empty_file_is_an_empty_log(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit")
        log.path.parent.mkdir(parents=True, exist_ok=True)
        log.path.write_text("", encoding="utf-8")

        assert log.verify_chain() == ()

    def test_an_unreadable_log_is_refused(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit")
        log.path.mkdir(parents=True)

        with pytest.raises(AuditLogError, match="cannot read"):
            log.verify_chain()

    def test_a_line_that_is_not_json_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        log.path.write_text("this is not a JSON entry\n", encoding="utf-8")

        with pytest.raises(AuditLogError, match="JSON"):
            log.verify_chain()

    def test_an_entry_that_chains_to_the_wrong_parent_is_detected(
        self, tmp_path: Path
    ) -> None:
        log, records = self._three(tmp_path)
        forged = _rehash(records[1] | {"prev_hash": GENESIS_HASH})
        _rewrite_lines(log.path, [records[0], forged, records[2]])

        with pytest.raises(AuditLogError, match="chains to"):
            log.verify_chain()

    def test_a_head_that_is_not_json_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        log.head_path.write_text("not json", encoding="utf-8")

        with pytest.raises(AuditLogError, match="JSON"):
            log.verify_chain()

    def test_a_head_that_is_not_an_object_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        log.head_path.write_text("[]", encoding="utf-8")

        with pytest.raises(AuditLogError, match="JSON object"):
            log.verify_chain()

    def test_a_head_with_an_unknown_key_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["approved"] = True
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match="unknown key"):
            log.verify_chain()

    def test_a_head_missing_a_key_is_detected(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        del head["last_hash"]
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match="missing the 'last_hash' key"):
            log.verify_chain()

    @pytest.mark.parametrize("count", [-1, True, "3", 2.5])
    def test_a_bad_head_count_is_detected(
        self, tmp_path: Path, count: object
    ) -> None:
        log, _ = self._three(tmp_path)
        head = json.loads(log.head_path.read_text(encoding="utf-8"))
        head["count"] = count
        log.head_path.write_text(json.dumps(head), encoding="utf-8")

        with pytest.raises(AuditLogError, match="count must be a non-negative integer"):
            log.verify_chain()

    def test_an_unreadable_head_is_refused(self, tmp_path: Path) -> None:
        log, _ = self._three(tmp_path)
        log.head_path.unlink()
        log.head_path.mkdir()

        with pytest.raises(AuditLogError, match="cannot read"):
            log.verify_chain()


# ---------------------------------------------------------------------------
# The log is not the applier
# ---------------------------------------------------------------------------


class TestTheLogCannotApply:
    def test_the_audit_log_imports_no_store_and_no_write_path(self) -> None:
        tree = ast.parse(inspect.getsource(audit_module))
        modules = {
            node.module.split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }

        assert "write_path" not in modules
        assert "rule_manager" not in modules

    def test_the_audit_log_calls_nothing_that_commits_or_activates(self) -> None:
        tree = ast.parse(inspect.getsource(audit_module))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }

        assert not calls & {"commit", "activate", "apply", "publish", "install"}
