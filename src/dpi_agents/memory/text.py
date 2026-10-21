"""The shared text handling of the memory layer (`T4-06`).

One place, because two places is one too many: the semantic store and the
episodic memory both tokenise, and two tokenisers drift \u2014 and a retrieval
that ranks by one tokeniser and a memory that recalls by another is two
systems wearing one name.
"""

from __future__ import annotations

import re

__all__ = ["paragraphs", "tokens"]

#: The words that carry no retrieval signal. Small on purpose: a stopword list
#: is a policy, and a big one silently drops the word that mattered.
STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "was",
        "were",
        "which",
        "with",
    }
)

_TOKEN = re.compile(r"[a-z0-9]+")


def tokens(text: str) -> tuple[str, ...]:
    """The searchable words of `text`, lowercased and without the stopwords."""
    return tuple(
        token
        for token in _TOKEN.findall(text.casefold())
        if token not in STOPWORDS
    )


def paragraphs(text: str) -> tuple[str, ...]:
    """The text's paragraphs, in order, with the blank ones dropped.

    A blank line ends a paragraph. It is crude, and crude is right here: a
    paragraph is a unit a human wrote, so a quote from it is a quote a human can
    find.
    """
    parts = [part.strip() for part in re.split(r"\n\s*\n", text)]
    return tuple(part for part in parts if part)
