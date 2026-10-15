"""`T1-04` — a rule DSL whose rules say where they came from.

Provenance is the precondition for every auto-apply tier in Phase 6: an agent that
proposes "block `*.evil.example`" must be able to answer *who asked, on what
evidence, and under what authority* before anyone applies it to live traffic. A
rule that cannot answer that is a rule nobody can safely review, which is why the
planned test is two-part — provenance must survive a round-trip, and a rule
without provenance must not be auto-appliable.

**The load-bearing design decision: provenance is a sidecar, not part of the rule
set.** `_RuleState` holds `frozenset`s and is read by `should_block` on every
inspected packet, shared across threads and pickled to workers. Adding a
provenance record per rule to that would put an allocation and a lookup on the hot
path of the engine, to serve a question only the *control* path ever asks. So the
matching state is untouched and provenance is held alongside it, keyed by the
stable rule keys `D-16` introduced (`AppType.name` for apps, the literal string for
everything else).

The consequence worth stating: **provenance is not on the snapshot.** A worker
receiving a snapshot gets matching behaviour and no history, which is correct — it
cannot use provenance, and pickling it to every worker would cost every packet.
A reviewer goes through `RuleManager`, not the snapshot.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from dpi_engine.rule_manager import (
    Provenance,
    RuleKind,
    RuleManager,
    RuleManagerError,
    resolve_app_key,
)
from dpi_engine.types import AppType


def _provenance(**kwargs: object) -> Provenance:
    base = {
        "source": "agent:triage",
        "author": "triage-agent",
        "evidence": "observed 42 flows to evil.example",
    }
    base.update(kwargs)
    return Provenance(**base)  # type: ignore[arg-type]


class TestProvenanceRecord:
    def test_records_its_own_fields(self) -> None:
        prov = _provenance()
        assert prov.source == "agent:triage"
        assert prov.author == "triage-agent"
        assert "evil.example" in prov.evidence

    def test_requires_a_source(self) -> None:
        """Provenance with no source is not provenance.

        This is the whole point of the feature, so it is enforced at construction
        rather than by convention: an empty `source` would produce a rule that
        *looks* auditable and answers no question.
        """
        with pytest.raises((ValueError, RuleManagerError)):
            Provenance(source="", author="a", evidence="e")

    def test_timestamp_defaults_to_now(self) -> None:
        """A rule created without an explicit time still records when it appeared.

        Defaults rather than requires, because forcing every caller to pass a
        timestamp would make the common path noisier than it needs to be.
        """
        prov = _provenance()
        assert prov.created_at

    def test_is_hashable_and_frozen(self) -> None:
        """It lives in a dict beside the rules, so it must not be mutable."""
        prov = _provenance()
        with pytest.raises((AttributeError, TypeError)):
            prov.source = "something else"  # type: ignore[misc]

    def test_survives_a_json_round_trip(self) -> None:
        restored = Provenance.from_dict(_provenance().to_dict())
        assert restored == _provenance()


class TestRuleIdentity:
    """Every rule needs one stable key, or provenance cannot be attached to it."""

    def test_ips_are_keyed_by_address(self) -> None:
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        assert manager.provenance_for("ip", "10.0.0.1") is not None

    def test_apps_are_keyed_by_enum_name(self) -> None:
        """`D-16`'s stable vocabulary, not the display name.

        Keying by display name would re-introduce the exact instability `D-16`
        fixed: reword the product and every stored provenance record silently
        detaches from its rule.
        """
        manager = RuleManager()
        manager.block_app(AppType.YOUTUBE, provenance=_provenance())

        assert manager.provenance_for("app", "YOUTUBE") is not None
        assert manager.provenance_for("app", "YouTube") is None, (
            "the display name must not be an identity; it is presentation copy"
        )

    def test_domains_and_ports_are_keyed_by_value(self) -> None:
        manager = RuleManager()
        manager.block_domain("evil.example", provenance=_provenance())
        manager.block_port(443, provenance=_provenance())

        assert manager.provenance_for("domain", "evil.example") is not None
        assert manager.provenance_for("port", "443") is not None

    def test_cidrs_are_keyed_by_their_canonical_text(self) -> None:
        """`D-20` territory: a subnet is keyed by its canonical network text.

        Normalisation happens at all because the same network can be written more
        than one way, and a provenance record attached to a *spelling* rather than
        to the rule would detach the moment the file was rewritten.
        """
        manager = RuleManager()
        manager.block_cidr("10.0.0.0/8", provenance=_provenance())

        assert manager.provenance_for("cidr", "10.0.0.0/8") is not None
        assert manager.provenance_for("cidr", "10.0.0.0/24") is None, (
            "a genuinely different network must not resolve to the same record"
        )

    def test_a_host_bit_spooled_cidr_is_still_rejected(self) -> None:
        """Normalising provenance keys must not soften the parser.

        `_parse_cidr` rejects `10.0.0.1/8` as "host bits set", and it must stay
        rejected. An earlier version normalised provenance keys with
        `strict=False`, which would have folded exactly that invalid spelling into
        a valid rule's identity -- so two spellings would share one audit record
        while only one of them was a rule at all.
        """
        manager = RuleManager()
        with pytest.raises(RuleManagerError, match="host bits"):
            manager.block_cidr("10.0.0.1/8", provenance=_provenance())

    def test_an_unknown_kind_is_rejected(self) -> None:
        """A typo in a kind must not silently return "no provenance"."""
        with pytest.raises((ValueError, RuleManagerError)):
            RuleManager().provenance_for("hostname", "x")

    def test_provenance_for_an_unknown_rule_is_none_not_an_error(self) -> None:
        """Absence is the normal answer; only a bad *query* is an error."""
        manager = RuleManager()
        assert manager.provenance_for("ip", "10.0.0.1") is None


class TestProvenanceThroughRuleLifecycle:
    """Provenance has to follow a rule through being set and unset."""

    def test_unblocking_removes_the_provenance(self) -> None:
        """A removed rule must not leave an orphan record behind.

        Otherwise a stale record would sit in the rules file claiming a rule exists
        that no longer does — and a reviewer would have to know to check.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        manager.unblock_ip("10.0.0.1")

        assert manager.provenance_for("ip", "10.0.0.1") is None

    def test_reblocking_replaces_rather_than_accumulates(self) -> None:
        """A rule has one origin, the latest one.

        Merging provenance from two sources would produce a record claiming a
        joint authorship that nobody declared.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance(author="first"))
        manager.block_ip("10.0.0.1", provenance=_provenance(author="second"))

        prov = manager.provenance_for("ip", "10.0.0.1")
        assert prov is not None and prov.author == "second"

    def test_a_rule_added_without_provenance_has_none(self) -> None:
        """The common case stays possible.

        Requiring provenance at insertion would break every existing caller and
        every existing rules file; the gate belongs at *apply* time, not at
        authoring time.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1")
        assert manager.provenance_for("ip", "10.0.0.1") is None


class TestPersistenceRoundTrip:
    """The planned test: provenance must survive a save/load cycle."""

    def test_round_trips_through_a_file(self, tmp_path: Path) -> None:
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        manager.block_app(AppType.YOUTUBE, provenance=_provenance(author="a2"))
        manager.block_domain("evil.example", provenance=_provenance(author="a3"))
        manager.block_port(443, provenance=_provenance(author="a4"))
        manager.block_cidr("192.168.0.0/16", provenance=_provenance(author="a5"))

        path = tmp_path / "rules.json"
        manager.save_rules(path)
        restored = RuleManager.load_rules(path)

        assert restored.provenance_for("ip", "10.0.0.1") is not None
        assert restored.provenance_for("app", "YOUTUBE") is not None
        assert restored.provenance_for("domain", "evil.example") is not None
        assert restored.provenance_for("port", "443") is not None
        assert restored.provenance_for("cidr", "192.168.0.0/16") is not None

    def test_authors_survive_individually(self, tmp_path: Path) -> None:
        """Not just "provenance is there" — the *right* provenance.

        A round-trip that collapsed every record into one, or kept only the first,
        would pass a presence check and be useless to a reviewer.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance(author="alice"))
        manager.block_ip("10.0.0.2", provenance=_provenance(author="bob"))

        path = tmp_path / "rules.json"
        manager.save_rules(path)
        restored = RuleManager.load_rules(path)

        assert restored.provenance_for("ip", "10.0.0.1").author == "alice"
        assert restored.provenance_for("ip", "10.0.0.2").author == "bob"

    def test_matching_behaviour_is_unchanged_by_the_round_trip(
        self, tmp_path: Path
    ) -> None:
        """Provenance is metadata; it must not perturb enforcement.

        Without this, a rule could block correctly before saving and behave
        differently after loading, which would be the worst possible bug for a
        tool whose job is blocking traffic.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        manager.block_app(AppType.YOUTUBE, provenance=_provenance())
        manager.block_cidr("192.168.0.0/16", provenance=_provenance())

        path = tmp_path / "rules.json"
        manager.save_rules(path)
        restored = RuleManager.load_rules(path)

        before = manager.snapshot().should_block("10.0.0.1", 80, AppType.HTTP)
        after = restored.snapshot().should_block("10.0.0.1", 80, AppType.HTTP)
        assert before == after
        assert after is not None

    def test_a_file_without_provenance_still_loads(self, tmp_path: Path) -> None:
        """Backwards compatibility is not optional.

        Every rules file written before this exists has no `provenance` key. They
        must load unchanged, and simply have no provenance — otherwise this feature
        would make every existing deployment unbootable.
        """
        legacy = {
            "blocked_ips": ["10.0.0.1"],
            "blocked_apps": ["YOUTUBE"],
            "blocked_domains": ["evil.example"],
            "blocked_ports": [443],
        }
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(legacy), encoding="utf-8")

        manager = RuleManager.load_rules(path)

        assert manager.provenance_for("ip", "10.0.0.1") is None
        assert manager.is_ip_blocked("10.0.0.1")
        assert manager.snapshot().should_block("10.0.0.1", 443, AppType.YOUTUBE)

    def test_a_corrupt_provenance_block_does_not_lose_the_rules(
        self, tmp_path: Path
    ) -> None:
        """A bad record must not take the whole rule set down with it.

        The rules are the load-bearing thing; provenance is the audit trail. An
        unreadable audit entry is a reason to distrust *that rule's origin*, not to
        stop blocking the traffic the operator asked to block.
        """
        document = {
            "blocked_ips": ["10.0.0.1", "10.0.0.2"],
            "provenance": {"ip": {"10.0.0.1": {"author": 42, "source": ""}}},
        }
        path = tmp_path / "rules.json"
        path.write_text(json.dumps(document), encoding="utf-8")

        manager = RuleManager.load_rules(path)

        assert manager.is_ip_blocked("10.0.0.1")
        assert manager.is_ip_blocked("10.0.0.2")

    def test_provenance_survives_a_dict_round_trip_without_a_file(self) -> None:
        """The in-memory path matters too — `T0-03`'s live-rule tests use it."""
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())

        restored = RuleManager.from_dict(manager.to_dict())

        assert restored.provenance_for("ip", "10.0.0.1") is not None


class TestAutoApplyGate:
    """The gate that makes provenance worth having."""

    def test_a_rule_without_provenance_is_not_auto_appliable(self) -> None:
        """The precondition for Phase 6, stated as a test.

        "Auto-appliable" means: safe for an automated system to put into the live
        path without a human reading it first. A rule nobody can trace is not.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1")  # no provenance

        assert not manager.is_auto_appliable("ip", "10.0.0.1")

    def test_a_rule_with_provenance_is_auto_appliable(self) -> None:
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        assert manager.is_auto_appliable("ip", "10.0.0.1")

    def test_an_agent_sourced_rule_can_be_gated_out(self) -> None:
        """Provenance has to be able to say *no*, not just record a fact.

        The point of carrying the author is that policy can be written against it —
        an agent-proposed rule is precisely the one a human should see. So the
        record must be inspectable enough to make that decision.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance(source="agent:triage"))

        prov = manager.provenance_for("ip", "10.0.0.1")
        assert prov is not None
        assert prov.is_agent_sourced

    def test_a_human_sourced_rule_is_not_flagged_as_agent(self) -> None:
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance(source="operator:alice"))
        prov = manager.provenance_for("ip", "10.0.0.1")
        assert prov is not None and not prov.is_agent_sourced

    def test_the_gate_rejects_an_unknown_kind(self) -> None:
        with pytest.raises((ValueError, RuleManagerError)):
            RuleManager().is_auto_appliable("nonsense", "x")

    def test_audit_lists_every_rule_with_provenance(self) -> None:
        """A reviewer needs the whole list, not a lookup per rule."""
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance(author="alice"))
        manager.block_ip("10.0.0.2")
        manager.block_app(AppType.YOUTUBE, provenance=_provenance(author="bob"))

        audit = manager.audit()

        assert len(audit) == 2, "only rules that actually have provenance"
        assert {entry.provenance.author for entry in audit} == {"alice", "bob"}

    def test_audit_entries_identify_their_rule(self) -> None:
        """An audit entry that does not say which rule it describes is useless."""
        manager = RuleManager()
        manager.block_app(AppType.YOUTUBE, provenance=_provenance())

        entry = manager.audit()[0]
        assert entry.kind == RuleKind.APP
        assert entry.key == "YOUTUBE"
        assert entry.provenance.author == "triage-agent"

    def test_an_empty_ruleset_audits_empty(self) -> None:
        assert RuleManager().audit() == []


class TestSnapshotIsUnaffected:
    """The reason provenance is a sidecar, asserted rather than assumed."""

    def test_the_snapshot_carries_no_provenance(self) -> None:
        """A snapshot must stay cheap to build, pickle and send to a worker.

        If provenance leaked in, every `snapshot()` would allocate a record per
        rule and every worker would unpickle history it cannot use.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())

        snapshot = manager.snapshot()

        assert not hasattr(snapshot, "provenance")
        assert "provenance" not in snapshot.to_dict()

    def test_snapshots_still_pickle(self) -> None:
        """Multiprocessing depends on this, and the sidecar must not break it."""
        import pickle

        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())

        assert pickle.loads(pickle.dumps(manager.snapshot())).version == manager.version

    def test_blocking_still_works_with_provenance_present(self) -> None:
        """Attaching provenance must not change enforcement."""
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())

        assert manager.snapshot().should_block("10.0.0.1", 443, AppType.HTTPS)

    def test_provenance_is_not_shared_between_managers(self) -> None:
        """Two managers must not alias one record.

        Provenance records are frozen, so sharing is harmless in principle — but
        the *map* must not be shared, or a rule added to one would appear in the
        other, which is a correctness bug rather than an efficiency one.
        """
        first = RuleManager()
        first.block_ip("10.0.0.1", provenance=_provenance())

        second = RuleManager()
        assert second.provenance_for("ip", "10.0.0.1") is None

    def test_a_port_rule_is_identical_across_every_spelling_that_parses(
        self,
    ) -> None:
        """The boundary that actually matters.

        `str(int(key))` looks redundant for `443` and `"443"`, which already
        stringify identically -- so a test using only those two spellings cannot tell
        a normaliser from no normaliser at all, and mutation testing showed exactly
        that: deleting the branch left every test green.

        The spellings that differ are those `_normalize_port` *accepts* but `str()`
        does not collapse: `"0443"` and `" 443 "` both parse to `443`. They are
        therefore real rules, and a record attached to the spelling rather than to
        the port would detach the moment the file was rewritten canonically.
        """
        manager = RuleManager()
        manager.block_port("0443", provenance=_provenance(author="alice"))

        assert manager.provenance_for("port", 443) is not None, (
            "a zero-padded port and an int port are the same rule"
        )
        assert manager.provenance_for("port", "443") is not None

        padded = RuleManager()
        padded.block_port(" 443 ", provenance=_provenance(author="bob"))
        assert padded.provenance_for("port", 443) is not None, (
            "a whitespace-padded port must normalise too"
        )
        assert padded.provenance_for("port", " 443 ") is not None

    def test_a_port_rule_is_identical_whether_given_as_int_or_str(self) -> None:
        """The two spellings of the same rule must share one provenance record.

        `block_port` accepts `int | str`, so callers legitimately use both. If the key
        were taken verbatim, the rule added as `443` and looked up as `"443"` would be
        different identities -- and the auto-apply gate would report "no provenance"
        for a rule that plainly has some. That is the single worst failure this feature
        could have, because it is silent and it fails *closed* on the review path while
        the rule is live.
        """
        manager = RuleManager()
        manager.block_port(443, provenance=_provenance())

        assert manager.provenance_for("port", "443") is not None
        assert manager.provenance_for("port", 443) is not None

        manager2 = RuleManager()
        manager2.block_port("443", provenance=_provenance())
        assert manager2.provenance_for("port", 443) is not None, (
            "adding as a string must be findable as an int"
        )


    def test_a_gate_check_with_the_other_spelling_still_agrees(self) -> None:
        """The gate itself, crossed over the int/str boundary."""
        manager = RuleManager()
        manager.block_port("443", provenance=_provenance())

        assert manager.is_auto_appliable("port", 443), (
            "the gate must not deny auto-apply over a spelling difference"
        )


    def test_a_cidr_lookup_agrees_with_what_the_parser_accepted(self) -> None:
        """A key must resolve identically however it is spelled, *within* what is legal.

        The normaliser is `strict=True`, matching `_parse_cidr`. So every spelling the
        parser accepts folds to one key, and a spelling it rejects is rejected here too
        rather than quietly resolving to an existing record.
        """
        manager = RuleManager()
        manager.block_cidr("10.0.0.0/8", provenance=_provenance(author="alice"))

        # Same network, spelled from the object form -- the canonical text an operator
        # would copy out of a report.
        assert manager.provenance_for("cidr", str(ipaddress.ip_network("10.0.0.0/8"))) is not None
        assert manager.provenance_for("cidr", "10.0.0.0/8") is not None

        # A different network must not resolve to it.
        assert manager.provenance_for("cidr", "10.1.0.0/16") is None

        # And the illegal spelling must not fold into a valid record either.
        with pytest.raises(ValueError):
            manager.provenance_for("cidr", "10.0.0.1/8")




class TestVersionIsNotDisturbed:
    """Provenance is metadata; it must not churn the live-rules machinery."""

    def test_attaching_provenance_does_not_bump_the_version(self) -> None:
        """`RuleBroadcaster` polls `version` to decide whether to re-ship a snapshot.

        So bumping it on a provenance-only change would wake every worker and
        pickle a fresh snapshot for a rule set whose *matching behaviour* has not
        changed at all. That is a real cost on a live run for no reason.
        """
        manager = RuleManager()
        manager.block_ip("10.0.0.1")
        before = manager.version

        manager.block_ip("10.0.0.1", provenance=_provenance())  # already present

        assert manager.version == before, (
            "declaring provenance for an existing rule changed the snapshot version"
        )

    def test_adding_a_new_rule_still_bumps_the_version(self) -> None:
        """The guard above must not have broken the real signal."""
        manager = RuleManager()
        before = manager.version
        manager.block_ip("10.0.0.1")
        assert manager.version > before

    def test_clearing_provenance_alone_does_not_bump_the_version(self) -> None:
        manager = RuleManager()
        manager.block_ip("10.0.0.1", provenance=_provenance())
        before = manager.version

        manager.block_ip("10.0.0.1")  # same rule, provenance=None -> cleared

        assert manager.version == before
        assert manager.provenance_for("ip", "10.0.0.1") is None


class TestAppKeyStability:
    def test_persisted_app_keys_use_the_enum_name(self, tmp_path: Path) -> None:
        """`D-16` must survive this change.

        A rules file that regressed to display names would still load — via the
        deprecated alias path — but would have lost the canonical vocabulary, and
        the provenance keys with it.
        """
        manager = RuleManager()
        manager.block_app(AppType.YOUTUBE, provenance=_provenance())

        document = json.loads(manager.to_dict() and json.dumps(manager.to_dict()))
        assert document["blocked_apps"] == ["YOUTUBE"]

        prov = document.get("provenance", {})
        assert prov.get("app", {}).get("YOUTUBE") is not None

    def test_a_display_name_key_does_not_resolve(self) -> None:
        """The deprecation path must not become a live alias again."""
        manager = RuleManager()
        manager.block_app(AppType.YOUTUBE, provenance=_provenance())
        assert manager.provenance_for("app", resolve_app_key.__name__) is None
