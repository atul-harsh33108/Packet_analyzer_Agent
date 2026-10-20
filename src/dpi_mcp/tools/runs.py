"""The three run-store tools (`T3-04`).

`AGENTIC_ARCHITECTURE.md`'s Layer 2 asks for `query_flows(filter, limit)`,
`get_flow_detail(five_tuple)` and `diff_runs(run_a, run_b)`. All three are thin
adapters: `T3-02`'s `RunStore` already has `query`, `flow` and `diff`, so this module is
**contract design, not capability**. What it decides is how an agent sees the answers.

**The decision it was carrying: a broken question is not a negative answer.**

* A *well-formed* five-tuple the run never saw is a **result** -- `{"found": False}`.
* A five-tuple that is not five integers is an **error** -- `ToolInputError`.

If both were `None`, an agent could not tell "I asked for the wrong thing" from "the
answer is no", and the wrong repair is the one it would reach for first: retry the
query instead of fixing it. The same rule runs through the filters, where it is
`FlowFilter`'s (`T3-02`): an unknown app name raises rather than matching nothing, and
this layer passes that through untouched. `ToolInputError` subclasses `ValueError`
because it is an input error, so a caller that catches `ValueError` catches both.

**`matched` and `returned` are both reported**, because a capped list is otherwise
indistinguishable from a short one. `T3-02` made the same argument for `events_omitted`:
a partial answer that cannot be shown to be partial is a wrong answer. So the tool never
asks the store to cap -- it queries in full, slices, and reports both numbers.

**`store_root` is an explicit argument rather than a module global**, for the reason
`T3-03` made `output` explicit: a tool whose configuration is ambient cannot be called
twice with different settings in one process, and it hides where a side effect or a read
actually goes. `T3-05` binds one root per server instead of exposing it to the agent.

**Results are the store's own wire format**, down to the flow codec: `query_flows` emits
the rows `flow_to_json` writes, and `get_flow_detail` reads its argument back through
the same five fields. An agent can take a row it just read and ask about it, and the
projection cannot drift between the two tools because there is only one.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dpi_engine.types import FiveTuple
from dpi_mcp.run_store import FlowFilter, RunRecord, RunStore, flow_to_json
from dpi_mcp.tools.errors import ToolInputError

__all__ = [
    "diff_runs",
    "get_flow_detail",
    "query_flows",
    "ruleset_fingerprint",
    "run_outcome",
]

#: The five fields of a five-tuple, in the order `flow_to_json` writes them. Named here
#: because it is the one part of the wire format a tool has to *read* rather than emit.
_FIVE_TUPLE_FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")


def ruleset_fingerprint(ruleset: object) -> str:
    """A stable fingerprint of the rules document a run was produced with.

    The store wants a caller-supplied fingerprint and will not invent one, because
    a hash of "whatever was loaded" looks authoritative while being unable to see
    a rule added to a live `RuleManager` mid-run. This hashes the *document the
    agent sent*, which is exactly what was in force. No rules is the empty string,
    not a hash of `null`.

    One home for it, because two tools produce stored runs (`T3-05`'s `run_dpi`
    and `T3-07`'s `stream_dpi_events`) and two hashes of the same document would
    be two facts.
    """
    if ruleset is None:
        return ""
    canonical = json.dumps(ruleset, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def run_outcome(record: RunRecord, *, output: str | Path | None = None) -> dict[str, Any]:
    """A stored run's results, without its flow table.

    The flows stay behind `query_flows`: a capture with a hundred thousand flows
    must not arrive as one message. Everything else comes from the store's own
    encoder, so there is no second projection of a record to drift from the
    first -- the `D-16` failure mode, in the one place it would be easiest to
    introduce.
    """
    payload = record.to_json()
    payload.pop("flows", None)
    payload.pop("event_log", None)
    if output is not None:
        payload["output"] = str(output)
    return payload

#: Inclusive bounds per field. A five-tuple arrives as data from an agent, and every
#: value the engine can produce is inside these. Checking them here turns a mistyped
#: address into an error; without it the typo is a well-formed tuple that matches
#: nothing, which is exactly the confident wrong answer this module exists to refuse.
_BOUNDS = {
    "src_ip": (0, 2**32 - 1),
    "dst_ip": (0, 2**32 - 1),
    "src_port": (0, 2**16 - 1),
    "dst_port": (0, 2**16 - 1),
    "protocol": (0, 2**8 - 1),
}


def _five_tuple(flow: object) -> FiveTuple:
    """The five-tuple `flow` names, or `ToolInputError` if it does not name one.

    Extra keys are ignored so that a row from `query_flows` -- which carries `app`,
    `hostname` and the rest -- can be passed straight back in. A *missing* key is an
    error rather than a default, because every default would be a guess at a
    five-tuple that the caller did not ask about.
    """
    if not isinstance(flow, Mapping):
        raise ToolInputError(
            f"flow must be an object with {list(_FIVE_TUPLE_FIELDS)}, got "
            f"{type(flow).__name__}. A five-tuple is not a list: the field order is not "
            "something a caller should have to recall."
        )

    fields: dict[str, int] = {}
    for name in _FIVE_TUPLE_FIELDS:
        if name not in flow:
            raise ToolInputError(
                f"flow is missing {name!r}; every five-tuple needs "
                f"{list(_FIVE_TUPLE_FIELDS)}"
            )
        value = flow[name]
        # `bool` is a subclass of `int`, so `True` would otherwise be accepted as a
        # port number -- and `get_flow_detail(run, {"src_port": True})` would answer
        # "this flow is not in that run" for a question nobody meant to ask.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolInputError(
                f"flow[{name!r}] must be an integer, got {value!r} "
                f"({type(value).__name__})"
            )
        low, high = _BOUNDS[name]
        if not low <= value <= high:
            raise ToolInputError(
                f"flow[{name!r}] must be between {low} and {high}, got {value}. No flow "
                "the engine records is outside that range, so this is a mistyped value "
                "rather than a flow that happens to be absent."
            )
        fields[name] = value

    return FiveTuple(
        src_ip=fields["src_ip"],
        dst_ip=fields["dst_ip"],
        src_port=fields["src_port"],
        dst_port=fields["dst_port"],
        protocol=fields["protocol"],
    )


def query_flows(
    run_id: str,
    *,
    store_root: str | Path,
    app: str | None = None,
    state: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    protocol: int | None = None,
    action: str | None = None,
    min_bytes: int | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    """Stored flows of one run, filtered and capped.

    Returns `run_id`, `flows`, and the two counts that make truncation visible:
    `matched` (flows the filter accepted) and `returned` (how many were sent).
    `matched > returned` means the answer is partial, and by how much.

    `limit=0` means no cap, following `report.render_detected_domains` rather than
    giving zero a second meaning.

    Filter arguments are `FlowFilter`'s, and so are its rules: `app` and `state` are
    checked against the engine's enum names, `hostname` is an **exact** case-insensitive
    match (`D-27`: substring matching produces confident wrong answers, and a filter
    used to narrow a result set is the last place to reintroduce it), and `ip` must
    parse and matches **either** endpoint (`DEC-06`). An unknown name raises instead of
    matching nothing, so a mistyped filter cannot read as a fact about the capture.
    """
    if limit < 0:
        raise ToolInputError(
            f"limit must be >= 0, got {limit}. Zero means no cap, not a negative count."
        )

    store = RunStore(store_root)
    # No `limit` here on purpose: the tool reports how many rows it withheld, so the cap
    # has to happen after the count is known. Asking the store to cap would need a second
    # read of the same file to recover `matched`.
    matched = store.query(
        run_id,
        filter=FlowFilter(
            app=app,
            state=state,
            hostname=hostname,
            ip=ip,
            protocol=protocol,
            action=action,
            min_bytes=min_bytes,
        ),
    )
    selected = matched if limit == 0 else matched[:limit]
    return {
        "run_id": run_id,
        "matched": len(matched),
        "returned": len(selected),
        "flows": [flow_to_json(flow) for flow in selected],
    }


def get_flow_detail(
    run_id: str, flow: object, *, store_root: str | Path
) -> dict[str, Any]:
    """One stored flow, or `{"found": False, "flow": None}`.

    `flow` is the five-tuple to look up: `src_ip`, `dst_ip`, `src_port`, `dst_port` and
    `protocol`, as emitted by `query_flows`. Extra keys -- a whole row, for instance --
    are ignored, so the output of one tool is valid input to this one. The stored row is
    returned in full, including the classification fields the lookup did not use.

    Absence is reported rather than raised: *"this flow is not in that run"* is a
    legitimate answer, and `found` distinguishes it from a field that merely came back
    empty. A five-tuple that is not five integers raises `ToolInputError`, so a
    mistyped address cannot arrive as a false negative.
    """
    record = RunStore(store_root).flow(run_id, _five_tuple(flow))
    return {
        "run_id": run_id,
        "found": record is not None,
        "flow": None if record is None else flow_to_json(record),
    }


def diff_runs(run_a: str, run_b: str, *, store_root: str | Path) -> dict[str, Any]:
    """What changed from `run_a` to `run_b`, as `RunDiff.to_json`.

    Signed and unclamped, in the argument's direction: `drop_rate_change_percent` is
    positive when `run_b` dropped a larger share than `run_a`, and
    `diff_runs(b, a)` reports the opposite of `diff_runs(a, b)`.

    It reports movement rather than judging it, which is `RunDiff`'s own decision:
    more dropped packets can mean a stricter policy working, and the tool has no way to
    know which was intended. What it does not do is hide the movement -- a diff that
    omitted a counter, or took a magnitude, would make a regression read as a
    recovery, which is the failure `T2-04` recorded.
    """
    return RunStore(store_root).diff(run_a, run_b).to_json()
