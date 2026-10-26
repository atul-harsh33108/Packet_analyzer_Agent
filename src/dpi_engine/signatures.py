"""The signature table (`T5-04`): what makes an app an app, and a matcher that says so.

**Why a conjunction and not a hash.** `T5-01` produces JA3/JA4, and a hash answers
one question -- "is this the same client as that other flow?" -- while saying
nothing about *why*. That is exactly the wrong shape for the thing this phase
exists to build: `T5-05` has to propose a signature an analyst can check, and
`T5-06`'s Critic has to be able to falsify it. "Offers TLS 1.3, no SNI, GREASE
present, these ciphers" is falsifiable; `8daaf6152771` is not. So a signature is a
**conjunction of predicates over one `FlowFeatures`**, and the shipped table's
single-predicate entries are conjunctions too, because a JA4 is itself a
conjunction of version, cipher list, extension list, ALPN and SNI-presence.

**What a match means, and what it does not.** A flow is identified when every
predicate of one or more signatures holds and **all of them agree on the app**.
If two signatures claim different apps for the same flow, the answer is `unknown`
with both ids in `matched`, because choosing between them by table order or by
specificity would be a coin flip dressed as evidence -- and the gate this module
implements is precisely "an unknown app is reported as unknown rather than as the
nearest match". There is no score, no ranking and no fallback. An empty table
identifies nothing, which is an honest state, not a broken one.

The overlap a table can prove -- two signatures with the same predicates, whatever
app they claim -- is refused when the table is built, because that table can never
mean what it says.

The field vocabulary
--------------------
Every matchable field is one field of `FlowFeatures`, plus the two certificate
names, and nothing is derived into a second home:

* **scalars**, compared for equality: `ja3`, `ja4`, `ja3s`, `ja4s`,
  `client_version`, `sni_present`, `server_cipher_suite`, `selected_alpn`,
  `http2_settings`, `certificate.issuer`, `certificate.subject`.
* **lists**, matched by membership: `cipher_suites`, `extensions`, `alpn`,
  `grease`, `server_extensions`, and `tls_versions` -- for which the predicate
  value is a **version**, not a `[version, count]` pair. The counts are a
  client-specific tally that JA3/JA4 already encode; matching them would make a
  signature depend on how many times a client repeated itself.

Three consequences are deliberate, and each is a way a fingerprint table usually
goes wrong:

* **No negation.** A signature is positive evidence. `sni_present: false` is a
  positive fact ("the client sent no SNI"), but there is no "not X" operator,
  because a signature that matches everything except one value is a category, not
  an app, and it would match every flow that showed nothing at all.
* **No empty values.** `""` and `null` are what an unobserved field reads as, so
  a predicate on either would match the absence of evidence. `http2_settings: ""`
  (a SETTINGS frame with no entries) is therefore not matchable either, for the
  same reason `T5-03` kept it distinct from `None`.
* **An unobserved field never matches.** `certificate.issuer: "CN=Corp"` does not
  match a flow whose certificate was never visible (TLS 1.3, or a split flight),
  which is why absence has to be asked for explicitly with a `false`.

A warning for whoever authors the table next, recorded where it will be read: a
client fingerprint and a server fingerprint in **one** conjunction claim that both
sides of the connection are the same app. Usually they are not -- a Chrome client
talking to an nginx server has two different owners -- so a signature should be
about one side, and the `app` label is the label its author assigned, not a proof
of ownership.

Strictness, and why it is worth the friction
--------------------------------------------
Tables are written by an agent (`T5-05`) and argued over by another (`T5-06`), so
every key is checked and an unknown one is refused rather than ignored: a typo'd
`all_off` that silently matched every flow would be the worst possible failure,
and it is the one a permissive loader produces. The same reason refuses an empty
conjunction (it matches every flow) and a duplicate predicate (it is noise from a
generator, and it makes the conjunction's length lie).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dpi_engine.flow_features import FlowFeatures

__all__ = [
    "DEFAULT_TABLE",
    "SIGNATURE_TABLE_VERSION",
    "Identification",
    "Predicate",
    "Signature",
    "SignatureTable",
]

#: Bumped when the on-disk shape changes. A table written for another version is
#: refused rather than interpreted through new field meanings, the same rule the
#: run store's schema follows.
SIGNATURE_TABLE_VERSION = 1

#: Scalar features, compared for equality, with the type their value must have.
_SCALAR_FIELDS: dict[str, type] = {
    "ja3": str,
    "ja4": str,
    "ja3s": str,
    "ja4s": str,
    "sni_present": bool,
    "client_version": int,
    "server_cipher_suite": int,
    "selected_alpn": str,
    "http2_settings": str,
    "certificate.issuer": str,
    "certificate.subject": str,
}

#: List features, matched by membership, with the type of one element.
_LIST_FIELDS: dict[str, type] = {
    "cipher_suites": int,
    "extensions": int,
    "alpn": str,
    "grease": int,
    "server_extensions": int,
    "tls_versions": int,
}

_TABLE_KEYS = frozenset({"version", "signatures"})
_SIGNATURE_KEYS = frozenset({"id", "app", "all_of"})
_PREDICATE_KEYS = frozenset({"field", "value"})


def _all_hold(predicates: tuple[Predicate, ...], observed: Mapping[str, Any]) -> bool:
    return all(predicate._holds_in(observed) for predicate in predicates)


@dataclass(frozen=True, slots=True)
class Predicate:
    """One feature and the value it must have. A conjunction is made of these."""

    field: str
    value: str | int | bool

    def _holds_in(self, observed: Mapping[str, Any]) -> bool:
        value = observed[self.field]
        if self.field in _LIST_FIELDS:
            return self.value in value
        # `sni_present is None` (no ClientHello) equals neither `True` nor `False`,
        # which is what keeps an unobserved flow from matching an absence.
        return bool(value == self.value)


@dataclass(frozen=True, slots=True)
class Signature:
    """A named app and the conjunction of predicates that argues for it.

    The invariants are enforced here, not in the JSON loader, because `T5-05`'s
    proposer builds signatures in memory: a table that can only be honest when it
    arrives through one door is not honest.
    """

    id: str
    app: str
    all_of: tuple[Predicate, ...]

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("a signature's id must not be blank")
        if not self.app.strip():
            raise ValueError(f"signature {self.id!r} has a blank app")
        if not self.all_of:
            raise ValueError(
                f"signature {self.id!r} has an empty all_of: with no predicates it "
                "matches every flow, which is not an app"
            )
        if len(set(self.all_of)) != len(self.all_of):
            raise ValueError(f"signature {self.id!r} lists the same predicate twice")

    def matches(self, features: FlowFeatures) -> bool:
        """True when every predicate holds for `features`.

        This is the half `T5-06`'s Critic needs: a proposal can be tested against a
        single flow without a table around it, which is how a signature is falsified.
        """
        return _all_hold(self.all_of, _observed(features))

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "app": self.app,
            "all_of": [
                {"field": predicate.field, "value": predicate.value}
                for predicate in self.all_of
            ],
        }


@dataclass(frozen=True, slots=True)
class Identification:
    """What the matcher answered: an app, or an explicit unknown.

    `matched` is every signature that held, in table order. It is non-empty while
    `app` is `None` when the table disagrees with itself -- a conflict to fix, not a
    result to round.
    """

    app: str | None
    matched: tuple[str, ...]

    @property
    def is_known(self) -> bool:
        return self.app is not None


@dataclass(frozen=True, slots=True)
class SignatureTable:
    """An ordered, validated set of signatures. Order affects nothing but `matched`."""

    signatures: tuple[Signature, ...]

    def __post_init__(self) -> None:
        seen_ids: set[str] = set()
        seen_predicates: dict[frozenset[Predicate], Signature] = {}
        for signature in self.signatures:
            if signature.id in seen_ids:
                raise ValueError(f"two signatures share the id {signature.id!r}")
            seen_ids.add(signature.id)

            # A conjunction that appears twice under two apps is the one ambiguity a
            # loader can prove: the table would answer by table order.
            key = frozenset(signature.all_of)
            previous = seen_predicates.get(key)
            if previous is not None:
                raise ValueError(
                    f"signatures {previous.id!r} ({previous.app}) and {signature.id!r} "
                    f"({signature.app}) have the same predicates"
                )
            seen_predicates[key] = signature

    def identify(self, features: FlowFeatures) -> Identification:
        """Which app this flow's features identify, or `None` for unknown."""
        # One projection for the whole table: `Signature.matches` would rebuild it
        # per signature, which is the same answer for more work.
        observed = _observed(features)
        matched = tuple(
            signature
            for signature in self.signatures
            if _all_hold(signature.all_of, observed)
        )
        apps = {signature.app for signature in matched}
        app = next(iter(apps)) if len(apps) == 1 else None
        return Identification(app=app, matched=tuple(signature.id for signature in matched))

    def to_json(self) -> dict[str, Any]:
        return {
            "version": SIGNATURE_TABLE_VERSION,
            "signatures": [signature.to_json() for signature in self.signatures],
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> SignatureTable:
        """Decode and validate a table. Every key is required and every field known."""
        if not isinstance(raw, Mapping):
            raise ValueError(f"the signature table must be an object, got {type(raw).__name__}")
        _only_keys(raw, _TABLE_KEYS, "the table")

        version = _required(raw, "version", "the table")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"the table's version must be an integer, got {type(version).__name__}")
        if version != SIGNATURE_TABLE_VERSION:
            raise ValueError(
                f"this table is version {version}, but this build reads "
                f"{SIGNATURE_TABLE_VERSION}. A table is refused rather than read "
                "through new field meanings."
            )

        entries = _required(raw, "signatures", "the table")
        if not isinstance(entries, list):
            raise ValueError(
                f"the table's signatures must be a list, got {type(entries).__name__}"
            )
        signatures = tuple(
            _signature_from_json(entry, index) for index, entry in enumerate(entries)
        )
        return cls(signatures=signatures)


# ---------------------------------------------------------------------------
# Reading one flow
# ---------------------------------------------------------------------------


def _observed(features: FlowFeatures) -> dict[str, Any]:
    """The vector as the matcher sees it, keyed by the field vocabulary.

    `tls_versions` is projected to the versions offered. The counts stay on the
    vector, where they are a fact about the client; a predicate asks which
    versions were offered.
    """
    certificate = features.certificate
    return {
        "ja3": features.ja3,
        "ja4": features.ja4,
        "ja3s": features.ja3s,
        "ja4s": features.ja4s,
        "sni_present": features.sni_present,
        "client_version": features.client_version,
        "server_cipher_suite": features.server_cipher_suite,
        "selected_alpn": features.selected_alpn,
        "http2_settings": features.http2_settings,
        "certificate.issuer": "" if certificate is None else certificate.issuer,
        "certificate.subject": "" if certificate is None else certificate.subject,
        "cipher_suites": features.cipher_suites,
        "extensions": features.extensions,
        "alpn": features.alpn,
        "grease": features.grease,
        "server_extensions": features.server_extensions,
        "tls_versions": tuple(version for version, _count in features.tls_versions),
    }


# ---------------------------------------------------------------------------
# The codec
# ---------------------------------------------------------------------------


def _signature_from_json(raw: Any, index: int) -> Signature:
    where = f"signatures[{index}]"
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be an object, got {type(raw).__name__}")
    _only_keys(raw, _SIGNATURE_KEYS, where)

    signature_id = _text(raw, "id", where)
    app = _text(raw, "app", where)

    entries = _required(raw, "all_of", where)
    if not isinstance(entries, list):
        raise ValueError(f"{where}.all_of must be a list, got {type(entries).__name__}")
    predicates = tuple(
        _predicate_from_json(entry, f"{where}.all_of", position)
        for position, entry in enumerate(entries)
    )
    return Signature(id=signature_id, app=app, all_of=predicates)


def _predicate_from_json(raw: Any, where: str, index: int) -> Predicate:
    place = f"{where}[{index}]"
    if not isinstance(raw, Mapping):
        raise ValueError(f"{place} must be an object, got {type(raw).__name__}")
    _only_keys(raw, _PREDICATE_KEYS, place)

    field = _text(raw, "field", place)
    if field in _SCALAR_FIELDS:
        expected = _SCALAR_FIELDS[field]
        kind = "scalar"
    elif field in _LIST_FIELDS:
        expected = _LIST_FIELDS[field]
        kind = "list element"
    else:
        known = ", ".join(sorted([*_SCALAR_FIELDS, *_LIST_FIELDS]))
        raise ValueError(f"{place}.field is not a feature: {field!r}. Known features: {known}")

    value = _required(raw, "value", place)
    _check_value(value, expected, field, kind, place)
    return Predicate(field=field, value=value)


def _check_value(value: Any, expected: type, field: str, kind: str, place: str) -> None:
    if value is None:
        raise ValueError(f"{place}.value must not be null: ask for absence with a fact")
    if isinstance(value, str) and not value:
        raise ValueError(
            f"{place}.value must not be an empty string: that is what an "
            "unobserved field reads as"
        )
    if expected is bool:
        if not isinstance(value, bool):
            raise ValueError(
                f"{place}.value must be a boolean for {field}, got {type(value).__name__}"
            )
        return
    if isinstance(value, bool) or not isinstance(value, expected):
        raise ValueError(
            f"{place}.value must be a {kind} of type {expected.__name__} for {field}, "
            f"got {type(value).__name__}"
        )


def _required(raw: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in raw:
        raise ValueError(f"{where} is missing the {key} field")
    return raw[key]


def _only_keys(raw: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"{where} has an unknown key {unknown[0]!r}")


def _text(raw: Mapping[str, Any], key: str, where: str) -> str:
    value = _required(raw, key, where)
    if not isinstance(value, str):
        raise ValueError(f"{where}.{key} must be a string, got {type(value).__name__}")
    return value


# ---------------------------------------------------------------------------
# The shipped table
# ---------------------------------------------------------------------------

#: The signatures this repository has published evidence for, and no others.
#:
#: `chrome-ja4` is the client behind JA4.md's worked example, whose
#: `t13d1516h2_8daaf6152771_e5627efa2ab1` is asserted in `tests/test_tls_fingerprint.py`.
#: `sliver-ja4s` is FoxIO's published server fingerprint for the Sliver C2 framework.
#:
#: Both are single predicates because a JA4/JA4S *is* a conjunction of version,
#: cipher and extension facts; spelling those out again as separate predicates
#: would duplicate the hash's definition in a second place. A SETTINGS-only
#: signature is deliberately absent: the Chrome SETTINGS fingerprint is real, but
#: it is a property many clients share, so it is supporting evidence and not an
#: identification -- which is the distinction `T5-05` has to respect when it
#: proposes a signature.
DEFAULT_TABLE = SignatureTable(
    signatures=(
        Signature(
            id="chrome-ja4",
            app="CHROME",
            all_of=(Predicate(field="ja4", value="t13d1516h2_8daaf6152771_e5627efa2ab1"),),
        ),
        Signature(
            id="sliver-ja4s",
            app="SLIVER",
            all_of=(Predicate(field="ja4s", value="t130200_1301_a56c5b993250"),),
        ),
    )
)
