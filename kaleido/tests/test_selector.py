from kaleido.selector import CarrierClass, Observation, score_carriers


def test_reliable_carrier_wins_over_fast_but_failing_carrier() -> None:
    now = 10_000.0
    observations = [
        Observation("tls", CarrierClass.TLS_STREAM, True, 180, 12, observed_at=now),
        Observation("tls", CarrierClass.TLS_STREAM, True, 220, 10, observed_at=now),
        Observation("quic", CarrierClass.QUIC_DATAGRAM, True, 70, 30, observed_at=now),
        Observation("quic", CarrierClass.QUIC_DATAGRAM, False, observed_at=now),
        Observation("quic", CarrierClass.QUIC_DATAGRAM, False, observed_at=now),
    ]

    assert score_carriers(observations, now=now)[0].carrier == "tls"


def test_recent_evidence_outweighs_stale_failure() -> None:
    now = 10_000.0
    observations = [
        Observation("udp", CarrierClass.OBFUSCATED_UDP, False, observed_at=now - 7_200),
        Observation("udp", CarrierClass.OBFUSCATED_UDP, True, 90, 20, observed_at=now),
        Observation("tls", CarrierClass.TLS_STREAM, True, 900, 2, observed_at=now),
    ]

    assert score_carriers(observations, now=now)[0].carrier == "udp"


def test_half_life_must_be_positive() -> None:
    try:
        score_carriers([], half_life_seconds=0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_slow_recovery_is_penalized_when_other_metrics_match() -> None:
    now = 10_000.0
    observations = [
        Observation("fast-recover", CarrierClass.TLS_STREAM, True, 100, 10, 200, observed_at=now),
        Observation(
            "slow-recover", CarrierClass.HTTPS_SEMANTIC, True, 100, 10, 9_000, observed_at=now
        ),
    ]

    assert score_carriers(observations, now=now)[0].carrier == "fast-recover"
