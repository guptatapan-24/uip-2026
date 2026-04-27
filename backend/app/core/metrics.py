from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from statistics import mean
from time import perf_counter
from typing import Callable


@dataclass
class MetricsStore:
    total_requests: int = 0
    decision_counts: Counter = field(default_factory=Counter)
    scenario_counts: Counter = field(default_factory=Counter)
    latencies_ms: list[float] = field(default_factory=list)
    cache_hits: int = 0
    cache_misses: int = 0
    false_approvals: int = 0
    false_blocks: int = 0

    def track_request(self, scenario_id: str | None, decision: str, latency_ms: float) -> None:
        self.total_requests += 1
        self.decision_counts[decision] += 1
        self.latencies_ms.append(latency_ms)
        if scenario_id:
            self.scenario_counts[scenario_id] += 1

    def track_cache(self, hit: bool) -> None:
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def track_demo_expectation(self, decision: str, expected: str | None) -> None:
        if not expected:
            return
        if decision == "allow" and expected in {"block", "flag"}:
            self.false_approvals += 1
        if decision == "block" and expected == "allow":
            self.false_blocks += 1

    def snapshot(self) -> dict:
        total_cache = self.cache_hits + self.cache_misses
        return {
            "total_requests": self.total_requests,
            "decision_counts": dict(self.decision_counts),
            "scenario_counts": dict(self.scenario_counts),
            "mean_latency_ms": round(mean(self.latencies_ms), 2) if self.latencies_ms else 0.0,
            "p95_latency_ms": round(sorted(self.latencies_ms)[int(max(len(self.latencies_ms) * 0.95 - 1, 0))], 2)
            if self.latencies_ms
            else 0.0,
            "cache_hit_rate": round((self.cache_hits / total_cache) * 100, 2) if total_cache else 0.0,
            "far": round((self.false_approvals / self.total_requests) * 100, 2) if self.total_requests else 0.0,
            "fbr": round((self.false_blocks / self.total_requests) * 100, 2) if self.total_requests else 0.0,
        }


metrics_store = MetricsStore()


def timed(operation: Callable[[], tuple[dict, bool]]) -> tuple[dict, float, bool]:
    start = perf_counter()
    result, cache_hit = operation()
    latency_ms = (perf_counter() - start) * 1000
    return result, latency_ms, cache_hit
