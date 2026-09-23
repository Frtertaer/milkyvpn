"""Per-network carrier scoring without persistent subscriber identifiers."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import StrEnum


class CarrierClass(StrEnum):
    TLS_STREAM = "tls-stream"
    HTTPS_SEMANTIC = "https-semantic"
    QUIC_DATAGRAM = "quic-datagram"
    OBFUSCATED_UDP = "obfuscated-udp"


@dataclass(frozen=True, slots=True)
class Observation:
    carrier: str
    carrier_class: CarrierClass
    success: bool
    handshake_ms: float | None = None
    goodput_mbps: float | None = None
    recovery_ms: float | None = None
    battery_cost: float = 0.0
    observed_at: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class CarrierScore:
    carrier: str
    value: float
    samples: int


def score_carriers(
    observations: list[Observation],
    *,
    now: float | None = None,
    half_life_seconds: float = 900.0,
) -> list[CarrierScore]:
    """Rank carriers using decayed local evidence and a small exploration bonus."""

    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be positive")
    current = time.time() if now is None else now
    grouped: dict[str, list[tuple[Observation, float]]] = {}
    for item in observations:
        age = max(0.0, current - item.observed_at)
        weight = math.exp(-math.log(2.0) * age / half_life_seconds)
        grouped.setdefault(item.carrier, []).append((item, weight))

    ranked: list[CarrierScore] = []
    for carrier, samples in grouped.items():
        total_weight = sum(weight for _, weight in samples)
        successes = sum(weight for item, weight in samples if item.success)
        reliability = successes / total_weight if total_weight else 0.0

        latency_values = [
            (item.handshake_ms, weight)
            for item, weight in samples
            if item.success and item.handshake_ms is not None
        ]
        latency_penalty = 0.0
        if latency_values:
            weighted_latency = sum(value * weight for value, weight in latency_values) / sum(
                weight for _, weight in latency_values
            )
            latency_penalty = min(weighted_latency / 5_000.0, 1.0)

        goodput_values = [
            (item.goodput_mbps, weight)
            for item, weight in samples
            if item.success and item.goodput_mbps is not None
        ]
        goodput_bonus = 0.0
        if goodput_values:
            weighted_goodput = sum(value * weight for value, weight in goodput_values) / sum(
                weight for _, weight in goodput_values
            )
            goodput_bonus = min(math.log1p(weighted_goodput) / math.log(101.0), 1.0)

        recovery_values = [
            (item.recovery_ms, weight)
            for item, weight in samples
            if item.success and item.recovery_ms is not None
        ]
        recovery_penalty = 0.0
        if recovery_values:
            weighted_recovery = sum(value * weight for value, weight in recovery_values) / sum(
                weight for _, weight in recovery_values
            )
            recovery_penalty = min(weighted_recovery / 10_000.0, 1.0)

        battery_penalty = sum(item.battery_cost * weight for item, weight in samples) / total_weight
        exploration = 0.08 / math.sqrt(len(samples) + 1)
        value = (
            0.72 * reliability
            + 0.18 * goodput_bonus
            - 0.18 * latency_penalty
            - 0.12 * recovery_penalty
            - 0.08 * min(max(battery_penalty, 0.0), 1.0)
            + exploration
        )
        ranked.append(CarrierScore(carrier=carrier, value=value, samples=len(samples)))

    return sorted(ranked, key=lambda item: (-item.value, item.carrier))
