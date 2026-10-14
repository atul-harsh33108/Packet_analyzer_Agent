"""Two-stage (load-balancer -> fast-path) dispatch, mirroring OSC's
LBManager/LoadBalancer/FPManager tiering.

Ports OSC/include/load_balancer.h + OSC/src/load_balancer.cpp, which the
first version of this port dropped entirely in favour of a single
reader-dispatches-to-N-workers hop.

=============================================================================
Why the tiering is worth keeping
=============================================================================
The original's architecture is:

    reader -> LB0..LBk-1 -> FP0..FPn-1 -> output

with two hash steps: `LBManager::getLBForPacket` picks an LB from the
five-tuple hash, then that LB's `selectFP` picks one of *its* FPs. Both steps
hash the same five-tuple, so the second step is just `hash % fps_per_lb`
within a shard -- total FP count is `k * fps_per_lb`.

In the original the LB tier was largely plumbing, and it is largely plumbing
    here too. It earns its keep for a different reason than parsing: it is a
    queue-decoupling and backpressure-isolation tier. The stages map onto:

    stage 1 (parent): read raw frames off the byte stream and parse
        Ethernet/IP/TCP/UDP, compute the five-tuple, hash-select the owning
        load balancer, forward the parsed `WorkItem`.
    stage 2 (LB process): hash-select one of *its* own fast paths from the
        five-tuple and forward. `_lb_main` never parses; it receives
        pre-parsed `WorkItem`s and only calls `select_fp`.
    stage 3 (FP process): flow-table lookup, TCP state machine, classification
        (SNI / HTTP Host / DNS / QUIC), rule check, forward-or-drop decision.

    An earlier version of this module claimed the LB stage did the parsing, and
    that the staged pipeline therefore parallelised parse cost that the
    single-tier path serialises. That is wrong, and it contradicted both
    `docs/DESIGN_DECISIONS.md` and the root `README.md`: the reader must parse
    before it can hash a five-tuple, so the parse is the serial stage in every
    variant and the extra hop makes the two-tier path slightly *slower*. Use
    this variant for architecture parity and per-shard observability; use
    `run_pipeline_multiprocess` for speed.

=============================================================================
Consistency guarantees
=============================================================================
The partitioning invariant is the same in both: every packet of a given
five-tuple lands on the same fast-path process, so per-flow state (TCP
lifecycle, classification, block decisions) is never split. Within a
fast-path, packets are processed in strict FIFO order off its own queue, so
per-flow *ordering* is also preserved. Across fast-paths there is no ordering,
which is why the output pcap is reassembled in the parent using each item's
`sequence_index` rather than in completion order.

`hash_select` is deliberately NOT Python's builtin `hash()`: that is salted
per process for str/bytes and would partition differently in every worker.
FiveTuple is a tuple of ints, whose hash is stable, but the selection is
spelled out here anyway so the property is obvious and testable rather than
incidental.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import Any

from dpi_engine.types import FiveTuple, canonical_flow_key

#: Sentinel pushed onto a queue to mean "no more input; drain and finish".
#: A bare ``None`` is used (never a WorkItem) so it is unambiguous and pickles
#: trivially. See `worker.SHUTDOWN_SENTINEL` for the identical FP-side
#: contract -- one sentinel type for the whole pipeline is deliberate.
SHUTDOWN_SENTINEL = None

#: Packet-number hint for the hash. Not a security parameter, but a fixed
#: value keeps the choice deterministic and reviewable rather than depending
#: on a builtin.
_HASH_SEED = 0x9E3779B9


#: Distinct mixing salts for the different levels of a multi-tier selection.
#:
#: The original computed both levels from the *same* hash modulo the *same*
#: modulus: `LBManager::getLBForPacket` did `hash % lbs_.size()` and
#: `LoadBalancer::selectFP` did `hash % num_fps_` (dpi_mt.cpp:343 too). With
#: the default 2 LBs x 2 FPs that is `hash % 2` twice, so the two levels
#: always agree and only 2 of the 4 fast-paths ever receive a packet -- half
#: the worker pool idles permanently. Reproduced faithfully it would be a
#: silent 2x waste; instead each level mixes in its own salt, so the levels
#: are independent and every fast-path gets work.
_SALT_TIER_1 = 0
_SALT_TIER_2 = 0x85EBCA6B


def flow_hash(tuple_: FiveTuple, salt: int = _SALT_TIER_1) -> int:
    """A stable, process-independent hash of a five-tuple.

    Combines all five fields with the same boost-hash mixing constant OSC used
    (types.h `FiveTupleHash`), so partitioning quality is at least as good as
    the original's. Unlike the original, this does not depend on `std::hash`,
    whose output is implementation-defined per type, and it takes a `salt` so
    successive levels of a multi-tier selection are independent.
    """
    h = salt & 0xFFFFFFFF
    for value in (tuple_.src_ip, tuple_.dst_ip, tuple_.src_port, tuple_.dst_port, tuple_.protocol):
        h ^= (value & 0xFFFFFFFF) + _HASH_SEED + ((h << 6) & 0xFFFFFFFF) + (h >> 2)
        h &= 0xFFFFFFFF
    return h


def hash_select(tuple_: FiveTuple, num_buckets: int, salt: int = _SALT_TIER_1) -> int:
    """Picks the owning bucket for `tuple_` in [0, num_buckets).

    Raises ValueError for num_buckets < 1 rather than dividing by zero: a
    misconfigured pipeline should fail loudly at startup, not silently route
    nothing.
    """
    if num_buckets < 1:
        raise ValueError(f"num_buckets must be >= 1, got {num_buckets}")
    return flow_hash(tuple_, salt) % num_buckets


# ---------------------------------------------------------------------------
# Per-stage statistics (ports LBStats / FPStats / AggregatedStats)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LoadBalancerStats:
    """Per-LB counters. Ports OSC's LoadBalancer::LBStats.

    `per_fp_packets` is keyed by fast-path id rather than by position, because
    each LB owns a *disjoint* set of fast-paths: positional counts could not be
    merged across LBs without silently conflating LB0's FP0 with LB1's FP0.
    Keying by id makes `combine` a plain dict merge, and lets the parent report
    a single per-fast-path view across the whole pipeline.
    """

    lb_id: int = 0
    packets_received: int = 0
    packets_dispatched: int = 0
    per_fp_packets: dict[int, int] = field(default_factory=dict)

    def combine(self, others: Sequence[LoadBalancerStats]) -> LoadBalancerStats:
        """Sums `self` and every entry in `others`.

        Starts from empty accumulators and folds `(self, *others)` in, so
        `self` is counted exactly once -- pre-seeding from `self` and then
        folding `self` again is an easy double-count to write.
        """
        total = LoadBalancerStats(lb_id=self.lb_id)

        for other in (self, *others):
            total.packets_received += other.packets_received
            total.packets_dispatched += other.packets_dispatched
            for fp_id, count in other.per_fp_packets.items():
                total.per_fp_packets[fp_id] = total.per_fp_packets.get(fp_id, 0) + count

        return total

    def to_dict(self) -> dict[str, int | dict[int, int]]:
        return {
            "lb_id": self.lb_id,
            "packets_received": self.packets_received,
            "packets_dispatched": self.packets_dispatched,
            "per_fp_packets": dict(sorted(self.per_fp_packets.items())),
        }


@dataclass(slots=True)
class FastPathStats:
    """Per-fast-path counters. Ports OSC's FastPathProcessor::FPStats, plus
    the extraction counters the original threw away."""

    fp_id: int = 0
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    connections_tracked: int = 0
    sni_extractions: int = 0
    http_host_extractions: int = 0
    dns_extractions: int = 0
    quic_extractions: int = 0
    classification_hits: int = 0
    flows_reaped: int = 0
    rule_updates_applied: int = 0

    def combine(self, others: Sequence[FastPathStats]) -> FastPathStats:
        total = FastPathStats(fp_id=self.fp_id)
        for other in (self, *others):
            total.packets_processed += other.packets_processed
            total.packets_forwarded += other.packets_forwarded
            total.packets_dropped += other.packets_dropped
            total.tcp_packets += other.tcp_packets
            total.udp_packets += other.udp_packets
            total.connections_tracked += other.connections_tracked
            total.sni_extractions += other.sni_extractions
            total.http_host_extractions += other.http_host_extractions
            total.dns_extractions += other.dns_extractions
            total.quic_extractions += other.quic_extractions
            total.classification_hits += other.classification_hits
            total.flows_reaped += other.flows_reaped
            total.rule_updates_applied += other.rule_updates_applied
        return total

    def to_dict(self) -> dict[str, int]:
        return {
            "fp_id": self.fp_id,
            "packets_processed": self.packets_processed,
            "packets_forwarded": self.packets_forwarded,
            "packets_dropped": self.packets_dropped,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "connections_tracked": self.connections_tracked,
            "sni_extractions": self.sni_extractions,
            "http_host_extractions": self.http_host_extractions,
            "dns_extractions": self.dns_extractions,
            "quic_extractions": self.quic_extractions,
            "classification_hits": self.classification_hits,
            "flows_reaped": self.flows_reaped,
            "rule_updates_applied": self.rule_updates_applied,
        }


@dataclass(slots=True)
class FastPath:
    """Bookkeeping for one fast-path process: its id, its input queue, and
    the LB that feeds it.

    The queue is typed as `Queue[Any]` because this module must not import
    `WorkItem` (worker.py imports this module for the sentinel and the stats
    type, so the dependency runs this way). The concrete payload type is
    enforced at the point of use in pipeline.py, where the type is known.
    """

    fp_id: int
    input_queue: Queue[Any]
    #: The LoadBalancer instance that owns this fast-path. Set by the parent
    #: when wiring the graph.
    owner: LoadBalancer | None = None


@dataclass(slots=True)
class LoadBalancer:
    """Bookkeeping for one load-balancer process: its id, its input queue, and
    the fast-paths it feeds.

    Deliberately a thin record of the *graph*, not the running logic: the
    running logic lives in `pipeline._lb_main` and `worker.worker_main`, because
    a `multiprocessing.Process` target has to be importable and picklable by
    name. Keeping the wiring here, next to the stats, is what lets the parent
    build and validate the whole graph before spawning anything.
    """

    lb_id: int
    input_queue: Queue[Any]
    fps: list[FastPath] = field(default_factory=list)
    fps_per_lb: int = 0
    #: `DEC-05`. Kept here rather than threaded through `select_fp` because it
    #: is part of the *wiring*: the parent's first hash step and this one must
    #: use the same key, or a flow's two directions can be split across the LB
    #: tier and then split again inside it -- the staged path's version of the
    #: single-tier dispatch bug.
    fold_bidirectional: bool = True

    def __post_init__(self) -> None:
        if not self.fps:
            raise ValueError(f"LB{self.lb_id} has no fast-paths to feed")
        self.fps_per_lb = len(self.fps)
        for fp in self.fps:
            fp.owner = self

    def select_fp(self, tuple_: FiveTuple) -> FastPath:
        """Hash-selects one of this LB's fast-paths for `tuple_`.

        Uses the second-level salt so this decision is independent of the
        first-level (load-balancer) selection -- see `_SALT_TIER_2` for why
        reusing one hash at both levels is a bug.

        `DEC-05`: hashes the *canonical* flow key, not `tuple_` itself. Both
        hash steps have to agree, or a conversation's two directions reach
        different fast-paths and each holds only half the flow's state -- which
        is exactly the split the sharding exists to prevent, reintroduced one
        tier down.
        """
        return self.fps[
            hash_select(
                canonical_flow_key(tuple_, self.fold_bidirectional),
                self.fps_per_lb,
                salt=_SALT_TIER_2,
            )
        ]

    def queue_for(self, tuple_: FiveTuple) -> Queue[Any]:
        return self.select_fp(tuple_).input_queue


def build_pipeline_graph(
    num_load_balancers: int,
    fps_per_lb: int,
    queue_factory: Callable[[], Any],
    fold_bidirectional: bool = True,
) -> tuple[list[LoadBalancer], list[FastPath]]:
    """Builds the LB -> FP wiring graph without starting anything.

    `queue_factory()` must return a fresh, unstarted queue. Fast-paths are
    numbered `lb_id * fps_per_lb + i`, so a fast-path's id says which stage fed
    it -- which is what makes the per-stage reports readable.

    `fold_bidirectional` is stamped onto every load balancer so that both hash
    steps in the graph key on the same flow identity (`DEC-05`).

    Returns (load_balancers, all_fast_paths).
    """
    if num_load_balancers < 1:
        raise ValueError(f"num_load_balancers must be >= 1, got {num_load_balancers}")
    if fps_per_lb < 1:
        raise ValueError(f"fps_per_lb must be >= 1, got {fps_per_lb}")

    all_fps: list[FastPath] = []
    lbs: list[LoadBalancer] = []

    for lb_id in range(num_load_balancers):
        fps = [
            FastPath(fp_id=lb_id * fps_per_lb + i, input_queue=queue_factory())
            for i in range(fps_per_lb)
        ]
        all_fps.extend(fps)
        lbs.append(
            LoadBalancer(
                lb_id=lb_id,
                input_queue=queue_factory(),
                fps=fps,
                fold_bidirectional=fold_bidirectional,
            )
        )

    return lbs, all_fps
