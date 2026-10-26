"""`T5-04`: the signature table, the matcher, and the corpus's vocabulary.

A signature says **which features make an app an app**, in the only form that can
say *why*: a conjunction of predicates over one flow's `FlowFeatures`. A hash says
"the same app as that other flow"; a conjunction says "offers TLS 1.3, no SNI,
GREASE present, this cipher list". The first cannot be argued with, the second
can, and `T5-06`'s Critic is the thing that has to argue with it.

The gate this file pins has two halves, and the second is the one that is easy to
get wrong: a signature identifies the app it was written for, **and a flow no
signature matches is `unknown` rather than the nearest signature**. Nearest-
neighbour matching would make this a similarity engine with no way to be wrong,
which is precisely the trait the corpus tests exist to catch. So there is no
score here, no ordering by confidence, and no fallback: the predicates either all
hold or they do not.

Fixtures are imported rather than rebuilt: the published ClientHello behind
JA4.md's ``t13d1516h2_8daaf6152771_e5627efa2ab1``, FoxIO's published Sliver
ServerHello, and the certificate flight whose issuer OpenSSL reported. That is
deliberate — a signature table whose tests restate its own constants proves
nothing about either.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import dpi_engine.signatures as signature_module
from dpi_engine.flow_features import FlowFeatures, observe_flow_features
from dpi_engine.signatures import (
    DEFAULT_TABLE,
    Predicate,
    Signature,
    SignatureTable,
)
from dpi_engine.types import AppType
from golden.corpus import build_client_hello, iter_cases
from test_flow_features import _client_hello, _server_flight
from test_tls_certificate import _CA_SUBJECT
from test_tls_fingerprint import (
    _SUPPORTED_VERSIONS,
    _server_version,
    build_server_hello,
    ja4_vector_hello,
)

#: The published JA4 that `ja4_vector_hello` carries.
CHROME_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"

#: FoxIO's published Sliver JA4S, and the ServerHello that carries it.
SLIVER_JA4S = "t130200_1301_a56c5b993250"


def sliver_server_hello() -> bytes:
    return build_server_hello(
        cipher=0x1301,
        extensions=(
            (_SUPPORTED_VERSIONS, _server_version(0x0304)),
            (0x0033, b""),
        ),
    )


def chrome_features() -> FlowFeatures:
    return observe_flow_features(ja4_vector_hello())


def sliver_features() -> FlowFeatures:
    return observe_flow_features(sliver_server_hello())


def _predicate(field: str, value: object) -> dict[str, Any]:
    return {"field": field, "value": value}


def _signature(signature_id: str, app: str, *predicates: tuple[str, object]) -> dict[str, Any]:
    return {
        "id": signature_id,
        "app": app,
        "all_of": [_predicate(field, value) for field, value in predicates],
    }


def _table(*signatures: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "signatures": list(signatures)}


def parse_table(*signatures: dict[str, Any]) -> SignatureTable:
    return SignatureTable.from_json(_table(*signatures))


# ---------------------------------------------------------------------------
# The format: a signature is a conjunction, and a table is a list of them
# ---------------------------------------------------------------------------


def test_a_signature_is_a_conjunction_of_feature_predicates() -> None:
    table = parse_table(
        _signature(
            "chrome-tls13-h2",
            "CHROME",
            ("ja4", CHROME_JA4),
            ("alpn", "h2"),
            ("sni_present", True),
        )
    )

    (signature,) = table.signatures
    assert signature.id == "chrome-tls13-h2"
    assert signature.app == "CHROME"
    assert signature.all_of == (
        Predicate(field="ja4", value=CHROME_JA4),
        Predicate(field="alpn", value="h2"),
        Predicate(field="sni_present", value=True),
    )


def test_a_table_round_trips_through_its_json_codec() -> None:
    raw = _table(
        _signature("chrome", "CHROME", ("ja4", CHROME_JA4)),
        _signature("sliver", "SLIVER", ("ja4s", SLIVER_JA4S), ("server_cipher_suite", 0x1301)),
    )

    assert SignatureTable.from_json(raw).to_json() == raw


def test_the_written_table_is_json_serialisable() -> None:
    """The table is stored and proposed as JSON, so `to_json` must be JSON."""
    table = parse_table(_signature("chrome", "CHROME", ("ja4", CHROME_JA4)))

    payload = table.to_json()

    assert json.loads(json.dumps(payload)) == payload


def test_the_shipped_table_survives_its_own_codec() -> None:
    assert SignatureTable.from_json(DEFAULT_TABLE.to_json()) == DEFAULT_TABLE


# ---------------------------------------------------------------------------
# The matcher: a conjunction holds or it does not
# ---------------------------------------------------------------------------


def test_a_signature_that_holds_names_the_app_it_identifies() -> None:
    table = parse_table(
        _signature("chrome", "CHROME", ("ja4", CHROME_JA4), ("alpn", "h2")),
    )

    found = table.identify(chrome_features())

    assert found.app == "CHROME"
    assert found.matched == ("chrome",)
    assert found.is_known is True


def test_a_flow_no_signature_matches_is_unknown() -> None:
    """The gate's second half: no nearest, no fallback, no score."""
    table = parse_table(_signature("sliver", "SLIVER", ("ja4s", SLIVER_JA4S)))

    found = table.identify(chrome_features())

    assert found.app is None
    assert found.matched == ()
    assert found.is_known is False


def test_an_empty_table_identifies_nothing() -> None:
    found = SignatureTable.from_json(_table()).identify(chrome_features())

    assert found.app is None
    assert found.matched == ()


def test_every_predicate_in_the_conjunction_must_hold() -> None:
    matching = parse_table(
        _signature("both", "CHROME", ("ja4", CHROME_JA4), ("alpn", "h2")),
    )
    assert matching.identify(chrome_features()).app == "CHROME"

    one_wrong = parse_table(
        _signature("both", "CHROME", ("ja4", CHROME_JA4), ("alpn", "h3")),
    )
    found = one_wrong.identify(chrome_features())
    assert found.app is None
    assert found.matched == ()


def test_a_list_field_is_matched_by_membership_not_by_equality() -> None:
    """`alpn: h2` asks "was h2 offered", not "was it the only protocol offered"."""
    offered = chrome_features()
    assert offered.alpn == ("h2",)

    table = parse_table(_signature("h2", "H2_CLIENT", ("alpn", "h2")))
    assert table.identify(offered).app == "H2_CLIENT"

    absent = parse_table(_signature("h3", "H3_CLIENT", ("alpn", "h3")))
    assert absent.identify(offered).app is None


def test_a_cipher_suite_is_matched_by_membership() -> None:
    offered = chrome_features()
    assert len(offered.cipher_suites) > 1

    table = parse_table(_signature("ecdhe", "ECDHE_CLIENT", ("cipher_suites", 0xC02B)))
    assert table.identify(offered).app == "ECDHE_CLIENT"

    table = parse_table(_signature("aead", "AEAD_CLIENT", ("cipher_suites", 0xCCAA)))
    assert table.identify(offered).app is None


def test_a_scalar_field_is_matched_by_equality() -> None:
    offered = chrome_features()
    table = parse_table(_signature("tls12", "OLD", ("client_version", 0x0301)))
    assert table.identify(offered).app is None

    table = parse_table(_signature("tls12", "OLD", ("client_version", 0x0303)))
    assert table.identify(offered).app == "OLD"


def test_an_offered_version_is_matched_by_version_not_by_its_count() -> None:
    """`tls_versions` is a histogram on the row; a signature asks which versions."""
    offered = observe_flow_features(_client_hello())
    assert dict(offered.tls_versions) == {0x0304: 1, 0x0303: 1}

    table = parse_table(_signature("v13", "TLS13", ("tls_versions", 0x0304)))
    assert table.identify(offered).app == "TLS13"

    table = parse_table(_signature("v10", "TLS10", ("tls_versions", 0x0301)))
    assert table.identify(offered).app is None


def test_a_certificate_name_is_matchable() -> None:
    served = observe_flow_features(_server_flight())
    assert served.certificate is not None

    table = parse_table(_signature("internal", "INTERNAL", ("certificate.issuer", _CA_SUBJECT)))
    assert table.identify(served).app == "INTERNAL"

    table = parse_table(_signature("other", "OTHER", ("certificate.issuer", "CN=Elsewhere")))
    assert table.identify(served).app is None


def test_an_unobserved_certificate_matches_no_certificate_predicate() -> None:
    """`certificate: None` is "not visible", so it must not match a *value*."""
    never = observe_flow_features(_server_flight(tls13=True, certificate=None))
    assert never.certificate is None

    table = parse_table(_signature("internal", "INTERNAL", ("certificate.issuer", _CA_SUBJECT)))
    assert table.identify(never).app is None
    assert table.identify(FlowFeatures()).app is None


def test_an_absent_sni_is_a_fact_but_an_observed_nothing_is_not() -> None:
    """`sni_present` is `False` for a hello without SNI and `None` for no hello."""
    without_sni = observe_flow_features(_client_hello(hostname=None))
    assert without_sni.sni_present is False

    table = parse_table(_signature("no-sni", "NO_SNI", ("sni_present", False)))
    assert table.identify(without_sni).app == "NO_SNI"
    # A flow that showed no ClientHello at all is not "a client without SNI".
    assert table.identify(FlowFeatures()).app is None
    # And a hello *with* SNI is not one without.
    assert table.identify(chrome_features()).app is None


def test_two_signatures_for_one_app_agree_on_the_answer() -> None:
    """Two ways of recognising one app is a table with more coverage, not a conflict."""
    table = parse_table(
        _signature("chrome-ja4", "CHROME", ("ja4", CHROME_JA4)),
        _signature("chrome-h2", "CHROME", ("ja4", CHROME_JA4), ("alpn", "h2")),
    )

    found = table.identify(chrome_features())

    assert found.app == "CHROME"
    assert found.matched == ("chrome-ja4", "chrome-h2")


def test_two_apps_that_both_match_are_unknown_not_the_nearest() -> None:
    """An overlapping table is a bug in the table, and the matcher must not hide it.

    Returning either app would be a coin flip dressed as evidence. `matched` says
    which signatures disagreed, so the conflict is visible to whoever can fix it.
    """
    table = parse_table(
        _signature("chrome-ja4", "CHROME", ("ja4", CHROME_JA4)),
        _signature("chrome-h2", "SPOOFER", ("ja4", CHROME_JA4), ("alpn", "h2")),
    )

    found = table.identify(chrome_features())

    assert found.app is None
    assert found.matched == ("chrome-ja4", "chrome-h2")


def test_a_more_specific_signature_does_not_rescue_a_conflict() -> None:
    """Specificity is not a tie-breaker: a longer conjunction is not a stronger vote."""
    table = parse_table(
        _signature("broad", "CHROME", ("ja4", CHROME_JA4)),
        _signature(
            "narrow",
            "NOT_CHROME",
            ("ja4", CHROME_JA4),
            ("alpn", "h2"),
            ("sni_present", True),
            ("client_version", 0x0303),
        ),
    )

    found = table.identify(chrome_features())

    assert found.app is None
    assert found.matched == ("broad", "narrow")


def test_table_order_does_not_change_the_answer() -> None:
    first = _signature("chrome", "CHROME", ("ja4", CHROME_JA4))
    second = _signature("sliver", "SLIVER", ("ja4s", SLIVER_JA4S))

    forwards = parse_table(first, second).identify(chrome_features())
    backwards = parse_table(second, first).identify(chrome_features())

    assert forwards.app == backwards.app == "CHROME"
    assert forwards.matched == backwards.matched


def test_identifying_the_same_flow_twice_gives_the_same_answer() -> None:
    table = parse_table(_signature("chrome", "CHROME", ("ja4", CHROME_JA4)))
    features = chrome_features()

    assert table.identify(features) == table.identify(features)


# ---------------------------------------------------------------------------
# Refusals: a table that cannot mean what it says is not loaded
# ---------------------------------------------------------------------------


def test_an_unknown_field_is_refused() -> None:
    with pytest.raises(ValueError, match="ja4x"):
        parse_table(_signature("typo", "APP", ("ja4x", CHROME_JA4)))


def test_an_unknown_top_level_key_is_refused() -> None:
    raw = _table(_signature("chrome", "CHROME", ("ja4", CHROME_JA4)))
    raw["comment"] = "a stray key"

    with pytest.raises(ValueError, match="comment"):
        SignatureTable.from_json(raw)


def test_an_unknown_signature_key_is_refused() -> None:
    signature = _signature("chrome", "CHROME", ("ja4", CHROME_JA4))
    signature["priority"] = 1

    with pytest.raises(ValueError, match="priority"):
        parse_table(signature)


def test_a_unknown_predicate_key_is_refused() -> None:
    signature = _signature("chrome", "CHROME", ("ja4", CHROME_JA4))
    signature["all_of"][0]["op"] = "contains"

    with pytest.raises(ValueError, match="op"):
        parse_table(signature)


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        pytest.param("version", {"signatures": []}, id="no-version"),
        pytest.param("signatures", {"version": 1}, id="no-signatures"),
        pytest.param("id", {"app": "A", "all_of": [{"field": "ja4", "value": "x"}]}, id="no-signature-id"),
        pytest.param("app", {"id": "a", "all_of": [{"field": "ja4", "value": "x"}]}, id="no-app"),
        pytest.param("all_of", {"id": "a", "app": "A"}, id="no-conjunction"),
    ],
)
def test_a_missing_key_is_refused_rather_than_defaulted(key: str, raw: dict[str, Any]) -> None:
    table = raw if "version" in raw or "signatures" in raw else _table(raw)

    with pytest.raises(ValueError, match=key):
        SignatureTable.from_json(table)


@pytest.mark.parametrize("key", ["field", "value"])
def test_a_predicate_missing_a_key_is_refused(key: str) -> None:
    predicate: dict[str, Any] = {"field": "ja4", "value": CHROME_JA4}
    del predicate[key]

    with pytest.raises(ValueError, match=key):
        SignatureTable.from_json(_table({"id": "a", "app": "A", "all_of": [predicate]}))


def test_an_empty_conjunction_is_refused() -> None:
    """A signature with no predicates matches every flow, which is not an app."""
    with pytest.raises(ValueError, match="all_of"):
        parse_table(_signature("everything", "EVERYTHING"))


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param("", "empty string", id="empty-string"),
        pytest.param([], "value", id="empty-list"),
        pytest.param(None, "null", id="null"),
    ],
)
def test_an_empty_or_null_value_is_refused(value: object, reason: str) -> None:
    """`""`/`null` are what an unobserved field reads as, so matching one is a trap."""
    with pytest.raises(ValueError, match=reason):
        parse_table(_signature("empty", "APP", ("ja4", value)))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("ja4", 7, id="int-for-a-string"),
        pytest.param("client_version", "0303", id="string-for-an-int"),
        pytest.param("client_version", True, id="bool-for-an-int"),
        pytest.param("sni_present", 1, id="int-for-a-bool"),
        pytest.param("alpn", 2, id="int-for-a-string-list"),
        pytest.param("cipher_suites", "1301", id="string-for-an-int-list"),
        pytest.param("alpn", ["h2"], id="list-for-a-scalar-list-element"),
    ],
)
def test_a_value_of_the_wrong_type_is_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError, match="value"):
        parse_table(_signature("bad", "APP", (field, value)))


@pytest.mark.parametrize("key", ["id", "app", "field"])
def test_a_name_that_is_not_a_string_is_refused(key: str) -> None:
    signature = _signature("chrome", "CHROME", ("ja4", CHROME_JA4))
    if key == "field":
        signature["all_of"][0]["field"] = 7
    else:
        signature[key] = 7

    with pytest.raises(ValueError, match=key):
        parse_table(signature)


def test_a_duplicate_predicate_is_refused() -> None:
    with pytest.raises(ValueError, match="twice"):
        parse_table(
            _signature("twice", "APP", ("ja4", CHROME_JA4), ("ja4", CHROME_JA4)),
        )


def test_a_duplicate_signature_id_is_refused() -> None:
    with pytest.raises(ValueError, match="chrome"):
        parse_table(
            _signature("chrome", "CHROME", ("ja4", CHROME_JA4)),
            _signature("chrome", "CHROME", ("alpn", "h2")),
        )


def test_two_apps_with_the_same_predicates_are_refused() -> None:
    """The one ambiguity a loader can prove: identical conjunctions, different claims."""
    with pytest.raises(ValueError, match="same predicates"):
        parse_table(
            _signature("one", "CHROME", ("ja4", CHROME_JA4), ("alpn", "h2")),
            _signature("two", "FIREFOX", ("alpn", "h2"), ("ja4", CHROME_JA4)),
        )


def test_one_app_with_the_same_predicates_twice_is_refused() -> None:
    with pytest.raises(ValueError, match="same predicates"):
        parse_table(
            _signature("one", "CHROME", ("ja4", CHROME_JA4)),
            _signature("two", "CHROME", ("ja4", CHROME_JA4)),
        )


def test_an_unknown_table_version_is_refused() -> None:
    raw = _table(_signature("chrome", "CHROME", ("ja4", CHROME_JA4)))
    raw["version"] = 2

    with pytest.raises(ValueError, match="version"):
        SignatureTable.from_json(raw)


@pytest.mark.parametrize(
    "version",
    [
        pytest.param("1", id="string-version"),
        pytest.param(True, id="bool-version"),
        pytest.param(None, id="null-version"),
        pytest.param(1.0, id="float-version"),
    ],
)
def test_a_version_that_is_not_an_integer_is_refused(version: object) -> None:
    raw: dict[str, Any] = {"version": version, "signatures": []}

    with pytest.raises(ValueError, match="integer"):
        SignatureTable.from_json(raw)


def test_a_signature_list_that_is_not_a_list_is_refused() -> None:
    with pytest.raises(ValueError, match="must be a list"):
        SignatureTable.from_json({"version": 1, "signatures": {}})


def test_a_signature_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ValueError, match="object"):
        SignatureTable.from_json({"version": 1, "signatures": ["chrome"]})


def test_a_conjunction_that_is_not_a_list_is_refused() -> None:
    """A dict of predicates is not a conjunction: it has keys, not entries."""
    with pytest.raises(ValueError, match="must be a list"):
        parse_table({"id": "a", "app": "A", "all_of": {"field": "ja4"}})


def test_a_predicate_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ValueError, match="object"):
        SignatureTable.from_json(
            _table({"id": "a", "app": "A", "all_of": ["ja4"]})
        )


def test_a_table_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ValueError, match="object"):
        SignatureTable.from_json([])  # type: ignore[arg-type]


@pytest.mark.parametrize("app", ["", "   "])
def test_an_empty_app_is_refused(app: str) -> None:
    with pytest.raises(ValueError, match="app"):
        parse_table(_signature("chrome", app, ("ja4", CHROME_JA4)))


def test_a_blank_id_is_refused() -> None:
    """`matched` names signatures by id, so a blank one would be invisible in the log."""
    with pytest.raises(ValueError, match="id"):
        parse_table(_signature("   ", "CHROME", ("ja4", CHROME_JA4)))


def test_a_word_that_is_not_a_field_cannot_be_matched_by_a_typo() -> None:
    """`server_extensions` and `extensions` are different facts; a near-miss is refused."""
    with pytest.raises(ValueError, match="extension"):
        parse_table(_signature("typo", "APP", ("extension", 0x0000)))


# ---------------------------------------------------------------------------
# The vocabulary: a signature can name an app the corpus knows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("app", [app.name for app in AppType])
def test_every_app_type_is_a_legal_signature_app(app: str) -> None:
    """The corpus labels flows with `AppType` names; the table must speak that language."""
    table = parse_table(_signature("some-signature", app, ("ja4", CHROME_JA4)))

    assert table.signatures[0].app == app


# ---------------------------------------------------------------------------
# The shipped table: the fingerprints this repository has published evidence for
# ---------------------------------------------------------------------------


def test_the_shipped_table_identifies_the_published_chrome_client() -> None:
    offered = chrome_features()
    assert offered.ja4 == CHROME_JA4

    assert DEFAULT_TABLE.identify(offered).app == "CHROME"


def test_the_shipped_table_identifies_the_published_sliver_server() -> None:
    served = sliver_features()
    assert served.ja4s == SLIVER_JA4S

    assert DEFAULT_TABLE.identify(served).app == "SLIVER"


def test_the_shipped_table_abstains_on_a_flow_that_showed_nothing() -> None:
    assert DEFAULT_TABLE.identify(FlowFeatures()).app is None


def test_the_shipped_table_abstains_on_every_corpus_flow() -> None:
    """The corpus's TLS traffic is one synthetic client, and the table has no claim on it.

    This is the gate's second half measured on the corpus the evaluation uses: 59
    flows across 33 captures, every one of them honestly unknown. A matcher that
    "recognised" them would be recognising the generator, and the next task's agent
    would then propose a signature for a client that does not exist.
    """
    seen = 0
    for case in iter_cases():
        for flow in case.expected:
            observed = observe_flow_features(build_client_hello(flow.hostname))
            found = DEFAULT_TABLE.identify(observed)
            assert found.app is None, f"{case.name}/{flow.hostname} matched {found.app}"
            seen += 1

    assert seen >= 59, f"only {seen} corpus flows were checked"


def test_a_signature_answers_whether_it_holds_without_a_table() -> None:
    """`T5-06`'s Critic tests a proposal against a flow; it does not need a table."""
    signature = Signature(
        id="chrome",
        app="CHROME",
        all_of=(Predicate(field="ja4", value=CHROME_JA4),),
    )

    assert signature.matches(chrome_features()) is True
    assert signature.matches(FlowFeatures()) is False


def test_an_empty_certificate_name_is_refused() -> None:
    """The same rule as any other empty value: `""` is what absence reads as."""
    with pytest.raises(ValueError, match="value"):
        parse_table(_signature("any", "ANY", ("certificate.issuer", "")))


def test_a_signature_is_immutable_and_comparable() -> None:
    first = Signature(id="a", app="A", all_of=(Predicate(field="ja4", value=CHROME_JA4),))
    second = Signature(id="a", app="A", all_of=(Predicate(field="ja4", value=CHROME_JA4),))

    assert first == second
    with pytest.raises(AttributeError):
        first.app = "B"  # type: ignore[misc]


def test_a_signature_built_in_memory_is_validated_like_one_that_was_parsed() -> None:
    """`T5-05` proposes signatures as objects, so the invariants cannot live in the loader."""
    with pytest.raises(ValueError, match="all_of"):
        Signature(id="empty", app="APP", all_of=())

    with pytest.raises(ValueError, match="twice"):
        Signature(
            id="twice",
            app="APP",
            all_of=(Predicate("ja4", CHROME_JA4), Predicate("ja4", CHROME_JA4)),
        )


def test_a_table_built_in_memory_is_validated_like_one_that_was_parsed() -> None:
    with pytest.raises(ValueError, match="share the id"):
        SignatureTable(
            signatures=(
                Signature(id="one", app="A", all_of=(Predicate("alpn", "h2"),)),
                Signature(id="one", app="B", all_of=(Predicate("alpn", "h3"),)),
            )
        )

    with pytest.raises(ValueError, match="same predicates"):
        SignatureTable(
            signatures=(
                Signature(id="one", app="A", all_of=(Predicate("alpn", "h2"),)),
                Signature(id="two", app="B", all_of=(Predicate("alpn", "h2"),)),
            )
        )


def test_every_matchable_field_is_a_field_of_the_projection() -> None:
    """A field the vocabulary names but `_observed` forgets would raise `KeyError`."""
    known = set(signature_module._SCALAR_FIELDS) | set(signature_module._LIST_FIELDS)

    assert known == set(signature_module._observed(FlowFeatures()))
