"""`T6-01` — the policy store: versioned, content-addressed, append-only.

**What this file is protecting.** Every later Phase 6 task either writes through
this store or reads what it holds, so the store's two failure shapes are the
ones that would poison the whole write path:

1. **A version that silently changes identity.** A version is the canonical
   policy document plus its provenance, addressed by a digest over exactly
   those bytes. Editing the document, the provenance, the note or the parent
   while keeping the id must raise -- a store that repaired the mismatch would
   let a reviewed proposal and an applied one differ with no error anywhere.
2. **A read that quietly rescues a damaged directory.** A corrupt version, a
   file whose name is not an id, and an unreadable active pointer all raise.
   Skipping them would make the store look tidier than it is, and `history`
   would report a shorter past than the one on disk.

The identity tests are the other half. `version_id` is content-addressed, so
*which* fields feed the digest is a behavioural decision: the per-field tests
below fail if the document, provenance, note or parent stops contributing. The
`created_at` field is deliberately outside the digest -- it is when the version
was published, not what was published -- and the idempotence test is what keeps
re-publishing identical content from minting a second identical version.

`restore` is not a rollback of the directory. It commits old content as a *new*
version whose parent is the version restored, so a revert is as audible in the
history as the change it undoes. Only `activate` moves the pointer, and it
moves one kind at a time.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from dpi_engine.rule_manager import Provenance, RuleManager
from dpi_engine.rule_store import (
    SCHEMA,
    PolicyKind,
    PolicyVersion,
    RuleStore,
    RuleStoreError,
    content_payload,
    digest_of,
    version_id_for,
)

T1 = "2026-10-26T09:00:00+00:00"
T2 = "2026-10-26T09:05:00+00:00"
T3 = "2026-10-26T09:10:00+00:00"


# ---------------------------------------------------------------------------
# Fixtures and builders
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> RuleStore:
    """A store whose clock advances by one second per call, so history is ordered."""
    ticks: Iterator[int] = itertools.count(1)
    return RuleStore(
        tmp_path / "policy",
        clock=lambda: f"2026-10-26T09:00:{next(ticks):02d}+00:00",
    )


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
    author: str = "operator:alice", created_at: str = T1, **overrides: Any
) -> Provenance:
    return Provenance(
        source="agent:policy", author=author, created_at=created_at, **overrides
    )


def edit(path: Path, change: dict[str, Any]) -> None:
    """Rewrites a stored record, preserving everything not named in `change`."""
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    raw.update(change)
    path.write_text(json.dumps(raw), encoding="utf-8")


# ---------------------------------------------------------------------------
# Round-tripping, and what "the document" means
# ---------------------------------------------------------------------------


def test_a_ruleset_round_trips_as_its_canonical_document(store: RuleStore) -> None:
    document = empty_ruleset(
        blocked_ips=["203.0.113.9"],
        blocked_apps=["YOUTUBE"],
        blocked_ports=[8443],
    )

    version = store.commit(PolicyKind.RULESET, document, note="reviewed")

    assert version.kind is PolicyKind.RULESET
    assert version.parent is None
    assert version.note == "reviewed"
    # The live counter in `RuleManager.to_dict` is not part of a policy document.
    assert "version" not in version.document
    # Normalisation completes the document, so a partial input and a full one
    # have one spelling (and therefore one id).
    assert set(version.document) == set(empty_ruleset())

    reopened = RuleStore(store.root)
    loaded = reopened.load(version.version_id)
    assert loaded == version
    assert RuleManager.from_dict(loaded.document).to_dict()["blocked_ips"] == [
        "203.0.113.9"
    ]


def test_a_signature_table_round_trips(store: RuleStore) -> None:
    version = store.commit(PolicyKind.SIGNATURES, signature_table())

    loaded = RuleStore(store.root).load(version.version_id)
    assert loaded.kind is PolicyKind.SIGNATURES
    assert loaded.document == signature_table()
    assert loaded.document["signatures"][0]["id"] == "sig-zoom"


def test_two_spellings_of_one_ruleset_are_one_version(store: RuleStore) -> None:
    first = store.commit(
        PolicyKind.RULESET,
        {"version": 7, "blocked_ips": ["203.0.113.9"]},
    )
    second = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"], blocked_ports=[], version=99),
    )

    assert second.version_id == first.version_id
    assert len(store.history()) == 1


def test_the_record_on_disk_is_the_whole_version(store: RuleStore) -> None:
    record = provenance()
    version = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"]),
        provenance=record,
        note="reviewed",
    )

    raw = json.loads(store.path_for(version.version_id).read_text(encoding="utf-8"))

    assert raw == {
        "schema": SCHEMA,
        "version_id": version.version_id,
        "kind": "ruleset",
        "parent": None,
        "document": version.document,
        "provenance": record.to_dict(),
        "note": "reviewed",
        "created_at": version.created_at,
    }


# ---------------------------------------------------------------------------
# Identity: which fields make a version a different version
# ---------------------------------------------------------------------------


def test_every_content_field_changes_the_version_id(store: RuleStore) -> None:
    base = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"]),
        provenance=provenance(),
        note="first",
    )
    assert base.version_id == base.computed_id

    other_document = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.10"]),
        provenance=provenance(),
        note="first",
    )
    other_provenance = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"]),
        provenance=provenance(author="operator:bob"),
        note="first",
    )
    other_note = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"]),
        provenance=provenance(),
        note="second",
    )

    assert len(
        {
            base.version_id,
            other_document.version_id,
            other_provenance.version_id,
            other_note.version_id,
        }
    ) == 4


def test_the_parent_changes_the_version_id(store: RuleStore) -> None:
    first = store.commit(PolicyKind.RULESET, empty_ruleset())
    rooted = store.commit(PolicyKind.RULESET, empty_ruleset(), parent=first.version_id)

    assert rooted.parent == first.version_id
    assert rooted.version_id != first.version_id
    assert rooted.computed_id == rooted.version_id


def test_a_new_provenance_timestamp_is_a_new_version(store: RuleStore) -> None:
    first = store.commit(
        PolicyKind.RULESET, empty_ruleset(), provenance=provenance(created_at=T1)
    )
    second = store.commit(
        PolicyKind.RULESET, empty_ruleset(), provenance=provenance(created_at=T2)
    )

    assert first.version_id != second.version_id
    assert len(store.history()) == 2


def test_committing_identical_content_twice_is_idempotent(tmp_path: Path) -> None:
    ticks = itertools.count(1)
    store = RuleStore(
        tmp_path / "policy",
        clock=lambda: f"2026-10-26T09:00:{next(ticks):02d}+00:00",
    )
    document = empty_ruleset(blocked_ips=["203.0.113.9"])

    first = store.commit(PolicyKind.RULESET, document)
    second = store.commit(PolicyKind.RULESET, document)

    assert second.version_id == first.version_id
    # First publication wins: the second call reports the stored version rather
    # than rewriting its publication time.
    assert second.created_at == first.created_at
    assert len(store.history()) == 1


# ---------------------------------------------------------------------------
# Refusals at the door: validation is the document's own loader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "document", "fragment"),
    [
        (PolicyKind.RULESET, {"blocked_ips": ["not-an-ip"]}, "Invalid IPv4"),
        (PolicyKind.RULESET, {"blocked_ports": ["not-a-port"]}, "port"),
        (PolicyKind.SIGNATURES, {"version": 1}, "signatures"),
        (PolicyKind.SIGNATURES, signature_table() | {"extra": True}, "unknown key"),
    ],
)
def test_a_malformed_document_is_refused_by_its_loader(
    store: RuleStore, kind: PolicyKind, document: object, fragment: str
) -> None:
    with pytest.raises(RuleStoreError, match=fragment):
        store.commit(kind, document)

    assert not (store.root / "versions").exists()


def test_a_document_with_a_wrongly_typed_field_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="not valid"):
        store.commit(PolicyKind.RULESET, {"blocked_ips": 5})


def test_a_commit_with_a_foreign_provenance_type_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="provenance"):
        store.commit(
            PolicyKind.RULESET,
            empty_ruleset(),
            provenance={"source": "operator:alice"},  # type: ignore[arg-type]
        )


def test_a_commit_with_a_non_string_note_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="note"):
        store.commit(PolicyKind.RULESET, empty_ruleset(), note=7)  # type: ignore[arg-type]


def test_a_default_clock_stamps_the_version(tmp_path: Path) -> None:
    store = RuleStore(tmp_path / "policy")

    version = store.commit(PolicyKind.RULESET, empty_ruleset())

    assert version.created_at.endswith("+00:00")


def test_an_unwritable_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "policy"
    root.mkdir()
    (root / "versions").write_text("not a directory", encoding="utf-8")
    store = RuleStore(root)

    with pytest.raises(RuleStoreError, match="cannot write"):
        store.commit(PolicyKind.RULESET, empty_ruleset())


def test_a_digest_collision_refuses_the_second_document(
    store: RuleStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Content addressing assumes no collisions; the store must not hide one."""
    from dpi_engine import rule_store as module

    monkeypatch.setattr(module, "digest_of", lambda payload: "0" * 16)
    first = store.commit(PolicyKind.RULESET, empty_ruleset(blocked_ips=["203.0.113.1"]))

    with pytest.raises(RuleStoreError, match="different content"):
        store.commit(PolicyKind.RULESET, empty_ruleset(blocked_ips=["203.0.113.2"]))

    assert first.version_id == "0" * 16


def test_a_document_that_is_not_an_object_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="JSON object"):
        store.commit(PolicyKind.RULESET, ["blocked_ips"])


def test_an_unknown_policy_kind_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="unknown policy kind"):
        store.commit("rules", empty_ruleset())

    with pytest.raises(RuleStoreError, match="unknown policy kind"):
        store.active("rules")


def test_a_kind_can_be_named_as_its_persisted_string(store: RuleStore) -> None:
    version = store.commit("signatures", signature_table())

    assert version.kind is PolicyKind.SIGNATURES
    assert store.active("signatures") is None


def test_a_parent_that_does_not_exist_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="no version"):
        store.commit(PolicyKind.RULESET, empty_ruleset(), parent="0" * 16)


def test_a_parent_of_another_kind_is_refused(store: RuleStore) -> None:
    other = store.commit(PolicyKind.SIGNATURES, signature_table())

    with pytest.raises(RuleStoreError, match="kind"):
        store.commit(PolicyKind.RULESET, empty_ruleset(), parent=other.version_id)


# ---------------------------------------------------------------------------
# A stored version is immutable
# ---------------------------------------------------------------------------


def test_an_edited_document_is_refused_on_load(store: RuleStore) -> None:
    version = store.commit(
        PolicyKind.RULESET, empty_ruleset(blocked_ips=["203.0.113.9"])
    )
    path = store.path_for(version.version_id)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["document"]["blocked_ips"] = ["198.51.100.7"]
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(RuleStoreError, match="hash"):
        store.load(version.version_id)


@pytest.mark.parametrize(
    "change",
    [
        {"note": "rewritten after review"},
        {"parent": "0" * 16},
        {"provenance": provenance(author="operator:mallory").to_dict()},
    ],
)
def test_edited_metadata_is_refused_on_load(
    store: RuleStore, change: dict[str, Any]
) -> None:
    version = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(),
        provenance=provenance(),
        note="reviewed",
    )
    edit(store.path_for(version.version_id), change)

    with pytest.raises(RuleStoreError, match="hash"):
        store.load(version.version_id)


def test_a_self_consistent_but_non_canonical_record_is_refused(
    store: RuleStore,
) -> None:
    """Even an editor who recomputes the digest cannot store a non-canonical document.

    The digest binds the bytes, so this file is *internally* consistent. The
    canonicalisation check is a second, independent invariant: `load` returns a
    document its loader accepts and `commit` would have written. Here the
    reintroduced `version` counter is stripped by normalisation, which proves
    the stored document was not the one this store published.
    """
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    forged_document = version.document | {"version": 5}
    forged_id = digest_of(
        content_payload(
            version.kind,
            version.parent,
            forged_document,
            version.provenance,
            version.note,
        )
    )
    forged = version.to_json() | {
        "version_id": forged_id,
        "document": forged_document,
    }
    store.path_for(forged_id).write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(RuleStoreError, match="canonical"):
        store.load(forged_id)


def test_a_version_filed_under_another_id_is_refused(store: RuleStore) -> None:
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    forged = store.path_for("0" * 16)
    forged.write_bytes(store.path_for(version.version_id).read_bytes())

    with pytest.raises(RuleStoreError, match="filed as"):
        store.load("0" * 16)


def test_a_missing_version_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="no version"):
        store.load("0" * 16)


@pytest.mark.parametrize(
    "bad_id",
    ["../../etc/passwd", "..", "0" * 15, "0" * 17, "ABCDEF0123456789", "0" * 15 + "g"],
)
def test_a_version_id_that_could_be_a_path_is_refused(
    store: RuleStore, bad_id: str
) -> None:
    with pytest.raises(RuleStoreError, match="not a version id"):
        store.path_for(bad_id)

    with pytest.raises(RuleStoreError, match="not a version id"):
        store.load(bad_id)


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def test_history_is_oldest_first_and_filterable(tmp_path: Path) -> None:
    stamps = iter((T1, T2, T3))
    store = RuleStore(tmp_path / "policy", clock=lambda: next(stamps))
    first = store.commit(PolicyKind.RULESET, empty_ruleset(blocked_ips=["203.0.113.1"]))
    second = store.commit(PolicyKind.RULESET, empty_ruleset(blocked_ips=["203.0.113.2"]))
    third = store.commit(PolicyKind.SIGNATURES, signature_table())

    assert [v.version_id for v in store.history()] == [
        first.version_id,
        second.version_id,
        third.version_id,
    ]
    assert [v.version_id for v in store.history("ruleset")] == [
        first.version_id,
        second.version_id,
    ]
    assert [v.version_id for v in store.history(PolicyKind.SIGNATURES)] == [
        third.version_id
    ]


def test_a_store_that_has_never_been_written_is_empty(tmp_path: Path) -> None:
    store = RuleStore(tmp_path / "nothing")

    assert store.history() == ()
    assert store.active(PolicyKind.RULESET) is None
    assert store.active(PolicyKind.SIGNATURES) is None


def test_history_refuses_a_corrupt_version_rather_than_skipping_it(
    store: RuleStore,
) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    corrupt = store.root / "versions" / "deadbeefdeadbeef.json"
    corrupt.write_text("{not json", encoding="utf-8")

    with pytest.raises(RuleStoreError, match="not valid JSON"):
        store.history()


def test_history_refuses_a_file_that_is_not_a_version_id(store: RuleStore) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    (store.root / "versions" / "scratch.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuleStoreError, match="not a version id"):
        store.history()


# ---------------------------------------------------------------------------
# Restore: a revert is a new version, not a rewrite of the past
# ---------------------------------------------------------------------------


def test_restore_commits_the_old_document_as_a_new_version(store: RuleStore) -> None:
    original = store.commit(
        PolicyKind.RULESET,
        empty_ruleset(blocked_ips=["203.0.113.9"]),
        provenance=provenance(created_at=T1),
        note="original",
    )
    store.activate(original.version_id)

    restored = store.restore(
        PolicyKind.RULESET,
        original.version_id,
        provenance=provenance(created_at=T2),
        note="revert",
    )

    assert restored.version_id != original.version_id
    assert restored.parent == original.version_id
    assert restored.kind is original.kind
    assert restored.document == original.document
    assert restored.note == "revert"
    # The original is untouched, and the revert did not move the pointer.
    assert store.load(original.version_id) == original
    assert store.active(PolicyKind.RULESET) == original
    assert [v.version_id for v in store.history()] == [
        original.version_id,
        restored.version_id,
    ]


def test_restore_refuses_a_version_of_another_kind(store: RuleStore) -> None:
    other = store.commit(PolicyKind.SIGNATURES, signature_table())

    with pytest.raises(RuleStoreError, match="signatures version"):
        store.restore(PolicyKind.RULESET, other.version_id)


def test_restore_of_a_missing_version_is_refused(store: RuleStore) -> None:
    with pytest.raises(RuleStoreError, match="no version"):
        store.restore(PolicyKind.RULESET, "0" * 16)


# ---------------------------------------------------------------------------
# The active pointer
# ---------------------------------------------------------------------------


def test_activate_moves_one_kind_and_survives_a_new_instance(store: RuleStore) -> None:
    rules = store.commit(PolicyKind.RULESET, empty_ruleset())
    signatures = store.commit(PolicyKind.SIGNATURES, signature_table())

    assert store.activate(rules.version_id) == rules
    assert store.active(PolicyKind.RULESET) == rules
    assert store.active(PolicyKind.SIGNATURES) is None

    assert store.activate(signatures.version_id) == signatures

    reopened = RuleStore(store.root)
    assert reopened.active(PolicyKind.RULESET) == rules
    assert reopened.active(PolicyKind.SIGNATURES) == signatures


def test_activate_refuses_a_missing_version_and_leaves_the_pointer_alone(
    store: RuleStore,
) -> None:
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    store.activate(version.version_id)

    with pytest.raises(RuleStoreError, match="no version"):
        store.activate("0" * 16)

    assert store.active(PolicyKind.RULESET) == version


def test_a_corrupt_active_pointer_is_refused(store: RuleStore) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    (store.root / "active.json").write_text("{", encoding="utf-8")

    with pytest.raises(RuleStoreError, match="active"):
        store.active(PolicyKind.RULESET)


def test_active_json_with_an_unknown_kind_is_refused(store: RuleStore) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    (store.root / "active.json").write_text(
        json.dumps({"schema": SCHEMA, "active": {"rules": None}}), encoding="utf-8"
    )

    with pytest.raises(RuleStoreError, match="unknown policy kind"):
        store.active(PolicyKind.RULESET)


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        ([], "JSON object"),
        ({"schema": SCHEMA, "active": {}, "extra": True}, "unknown key"),
        ({"active": {}}, "missing"),
        ({"schema": "other", "active": {}}, "schema"),
        ({"schema": SCHEMA, "active": []}, "active"),
        ({"schema": SCHEMA, "active": {"ruleset": "not-an-id"}}, "not a version id"),
    ],
)
def test_a_malformed_active_pointer_is_refused(
    store: RuleStore, payload: object, fragment: str
) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    (store.root / "active.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuleStoreError, match=fragment):
        store.active(PolicyKind.RULESET)


def test_an_active_pointer_to_a_missing_version_is_refused(store: RuleStore) -> None:
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    store.activate(version.version_id)
    store.path_for(version.version_id).unlink()

    with pytest.raises(RuleStoreError, match="no version"):
        store.active(PolicyKind.RULESET)


# ---------------------------------------------------------------------------
# The codec, directly
# ---------------------------------------------------------------------------


def test_a_record_with_an_unknown_field_is_refused(store: RuleStore) -> None:
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    raw = version.to_json() | {"unexpected": True}

    with pytest.raises(RuleStoreError, match="unknown"):
        PolicyVersion.from_json(raw)


def test_an_unreadable_provenance_record_is_refused_not_dropped(
    store: RuleStore,
) -> None:
    version = store.commit(
        PolicyKind.RULESET, empty_ruleset(), provenance=provenance()
    )
    raw = version.to_json()
    raw["provenance"] = {"source": "", "author": ""}

    with pytest.raises(RuleStoreError, match="provenance"):
        PolicyVersion.from_json(raw)


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("schema", "dpi-engine-rulestore/v2", "schema"),
        ("version_id", "not-an-id", "not a version id"),
        ("kind", "rules", "unknown policy kind"),
        ("parent", "not-an-id", "not a version id"),
        ("document", [], "document"),
        ("note", 7, "note"),
        ("created_at", "", "created_at"),
    ],
)
def test_a_record_with_a_bad_field_is_refused(
    store: RuleStore, field: str, value: object, fragment: str
) -> None:
    version = store.commit(PolicyKind.RULESET, empty_ruleset())
    raw = version.to_json() | {field: value}

    with pytest.raises(RuleStoreError, match=fragment):
        PolicyVersion.from_json(raw)


def test_a_record_with_a_missing_key_is_refused(store: RuleStore) -> None:
    raw = store.commit(PolicyKind.RULESET, empty_ruleset()).to_json()
    del raw["note"]

    with pytest.raises(RuleStoreError, match="missing"):
        PolicyVersion.from_json(raw)


def test_a_record_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(RuleStoreError, match="JSON object"):
        PolicyVersion.from_json([])


def test_a_record_with_a_non_string_kind_is_refused(store: RuleStore) -> None:
    raw = store.commit(PolicyKind.RULESET, empty_ruleset()).to_json() | {"kind": 5}

    with pytest.raises(RuleStoreError, match="unknown policy kind"):
        PolicyVersion.from_json(raw)


def test_a_version_file_that_is_not_an_object_is_refused(store: RuleStore) -> None:
    store.commit(PolicyKind.RULESET, empty_ruleset())
    store.path_for("0" * 16).write_text("[]", encoding="utf-8")

    with pytest.raises(RuleStoreError, match="JSON object"):
        store.load("0" * 16)


def _version_fields() -> dict[str, Any]:
    return {
        "version_id": "0" * 16,
        "kind": PolicyKind.RULESET,
        "parent": None,
        "document": empty_ruleset(),
        "provenance": None,
        "note": "",
        "created_at": T1,
    }


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"version_id": "nope"}, "not a version id"),
        ({"kind": "ruleset"}, "unknown policy kind"),
        ({"parent": "nope"}, "not a version id"),
        ({"document": []}, "document"),
        ({"note": 7}, "note"),
        ({"created_at": ""}, "created_at"),
    ],
)
def test_a_directly_constructed_version_is_checked(
    overrides: dict[str, Any], fragment: str
) -> None:
    with pytest.raises(RuleStoreError, match=fragment):
        PolicyVersion(**_version_fields() | overrides)


def test_a_document_that_cannot_be_json_is_refused() -> None:
    fields = _version_fields() | {"document": {"when": object()}}

    with pytest.raises(RuleStoreError, match="JSON data"):
        PolicyVersion(**fields)


# ---------------------------------------------------------------------------
# `version_id_for`: the id a commit would mint, without committing
# ---------------------------------------------------------------------------


def test_version_id_for_is_the_id_commit_mints(store: RuleStore) -> None:
    """`T6-02`'s proposal stores this id, so the two paths must be one formula."""
    document = empty_ruleset(blocked_ips=["203.0.113.9"])
    record = Provenance(source="agent:policy", author="policy", created_at=T1)

    predicted = version_id_for(
        PolicyKind.RULESET,
        document=document,
        provenance=record,
        note="blocked after review",
        parent=None,
    )
    committed = store.commit(
        PolicyKind.RULESET,
        document,
        provenance=record,
        note="blocked after review",
    )

    assert predicted == committed.version_id
    assert store.history() == (committed,)


def test_version_id_for_writes_nothing(store: RuleStore) -> None:
    version_id_for(PolicyKind.RULESET, document=empty_ruleset())

    assert store.history() == ()
    assert not store.path_for("0" * 16).exists()


def test_version_id_for_canonicalises_a_partial_document(store: RuleStore) -> None:
    partial = {"blocked_ips": ["203.0.113.9"]}
    full = empty_ruleset(blocked_ips=["203.0.113.9"])

    assert version_id_for(PolicyKind.RULESET, document=partial) == version_id_for(
        PolicyKind.RULESET, document=full
    )


def test_version_id_for_accepts_a_kind_string() -> None:
    assert version_id_for("ruleset", document=empty_ruleset()) == version_id_for(
        PolicyKind.RULESET, document=empty_ruleset()
    )


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"provenance": "agent:policy"}, "provenance"),
        ({"note": 7}, "note"),
        ({"parent": "not-an-id"}, "not a version id"),
        ({"kind": "rules"}, "unknown policy kind"),
        ({"document": []}, "document"),
    ],
)
def test_version_id_for_refuses_what_commit_would_refuse(
    overrides: dict[str, Any], fragment: str
) -> None:
    arguments: dict[str, Any] = {
        "kind": PolicyKind.RULESET,
        "document": empty_ruleset(),
    } | overrides

    with pytest.raises(RuleStoreError, match=fragment):
        version_id_for(**arguments)
