"""The injection classifier (`T4-02`).

Layer 7: *"Before any capture-derived string reaches an LLM, a cheap classifier
scans it. Anomalies -> quarantine the flow and route to human review."*

**What this is, precisely: a filter, not a control.** It catches the shapes of
hostile text it knows, it reports what it caught, and it says nothing about the
shapes it does not know. The protection against the shapes it does not know is
the other two layers -- the framing (the model is *told* the content is data)
and the capability restriction (the agent has no write tool, and `T4-01`'s
runtime cannot reach the network). That is why there are three layers and not
one classifier asked to be a guarantee.

**The coverage is the eval set, exactly.** `tests/injection_evals.py` holds the
hostile strings this is tested against, and the criterion is two-sided: 100% of
the hostile set is refused, and 0% of the benign set is refused. A number with
only one side is a number that can be won by making the tool worse.

**Normalisation before matching, because evasion is mostly typography.** An
attacker who cannot spell "ignore previous instructions" without a zero-width
space in it has not been stopped, so the classifier strips zero-width and
bidi-format characters, casefolds, and collapses whitespace before it matches.
The text the *model* sees is untouched \u2014 normalisation is for deciding, not for
rewriting.
"""

from __future__ import annotations

import dataclasses
import re

__all__ = ["InjectionVerdict", "classify", "normalise", "rules"]


@dataclasses.dataclass(frozen=True, slots=True)
class InjectionVerdict:
    """The classifier's answer about one string.

    `rule` names *which* pattern matched, so a refusal can be explained rather
    than merely asserted \u2014 an unexplained refusal is indistinguishable from a
    bug, and a bug in a classifier that refuses valid traffic is how a
    classifier gets switched off.
    """

    suspicious: bool
    rule: str | None = None


#: The zero-width and bidi-format characters, which carry no meaning in a
#: hostname and a great deal of meaning to an evasion.
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")

#: The separators between the words of a name.
#:
#: **This is the one that nearly got away.** The design's own example of a
#: hostile hostname is `ignore-previous-instructions.example.com` -- and a
#: hostname separates its words with *hyphens*, not with spaces. Rules written
#: for prose (which is how the rules were first written) match the phrase
#: "ignore previous instructions" and miss the hostname entirely. The
#: integration test in `tests/test_agent_triage.py` is what found it: the unit
#: test's hostile set was prose, so the classifier looked fine while the
#: design's own example walked straight through it.
_SEPARATORS = re.compile(r"[-._\s]+")


def normalise(text: str) -> str:
    """The form the rules match against.

    Casefolded, with invisible characters removed and **every word separator
    flattened to a space**. A hostname, a domain and a sentence are separated
    differently, and an attacker picks the one the reader is least likely to
    think about.
    """
    return " ".join(
        _SEPARATORS.sub(" ", _INVISIBLE.sub("", text).casefold()).split()
    )


#: The rules, in the order they are tried.
#:
#: Each is a named pattern, and the name is what a refusal reports. They are
#: deliberately *phrases* rather than keywords: "ignore" alone is a normal word
# in a report ("ignore cache entries"), and a classifier that refuses on it
# teaches its users to route around it.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(
            r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+"
            r"(?:instructions?|prompts?|directions?|commands?|rules?)"
        ),
    ),
    (
        "disregard_instructions",
        re.compile(
            r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|the\s+above)\s*"
            r"(?:instructions?|prompts?|directions?|rules?)"
        ),
    ),
    (
        "forget_instructions",
        re.compile(r"forget\s+(?:everything|all|your|previous|the\s+above)"),
    ),
    (
        "role_override",
        re.compile(
            r"you\s+are\s+now\b|\bnew\s+(?:role|persona|instructions?)\b|"
            r"\bact\s+as\s+(?:an?\s+)?(?:administrator|root|system|assistant|expert)"
        ),
    ),
    (
        "framing_tag",
        re.compile(r"<\s*/?\s*untrusted\s+capture\s+data\s*>"),
    ),
    (
        "instruction_delivery",
        re.compile(
            r"\b(?:execute|eval|run|invoke|perform)\s+(?:the\s+)?(?:following|this|these)\b"
        ),
    ),
    (
        "exfiltration",
        re.compile(
            r"\b(?:exfiltrate|leak|siphon)\b|\b(?:send|post|upload|transmit)\s+(?:the\s+)?"
            r"(?:contents?|data|file|files|key|keys|secret|secrets|credential|credentials)\b"
        ),
    ),
    (
        "credential_request",
        re.compile(
            # Bounded by **words**, not by characters: the normaliser has already
            # flattened the separators, so a character bound would quietly start
            # spanning sentences. The trailing `\s+` matters: the bound consumes
            # whole words, so without it the noun would have to follow the last
            # one *directly*, with no space.
            r"\b(?:api[_ -]?keys?|passwords?|secrets?|credentials?|tokens?)\b"
            r"(?:\s+\S+){0,8}\s+\b(?:send|post|include|reveal|share|print)\b"
            r"|\b(?:send|post|include|reveal|share|print)\b(?:\s+\S+){0,8}\s+"
            r"\b(?:api[_ -]?keys?|passwords?|secrets?|credentials?|tokens?)\b"
        ),
    ),
    (
        "tool_call_marker",
        re.compile(r"<\s*/?\s*tool\s+call\s*>|\bfunction\s+call\s*:|\bto=functions\b"),
    ),
)


def rules() -> tuple[str, ...]:
    """The rule names, for a report that says what is checked."""
    return tuple(name for name, _ in _RULES)


def classify(text: str) -> InjectionVerdict:
    """Whether `text` looks like an injection attempt.

    The answer is about *this string*. A flow is quarantined when one of its
    capture-derived strings is refused; that decision belongs to the caller,
    which knows the other fields of the flow.
    """
    flat = normalise(text)
    for name, pattern in _RULES:
        if pattern.search(flat):
            return InjectionVerdict(suspicious=True, rule=name)
    return InjectionVerdict(suspicious=False)
