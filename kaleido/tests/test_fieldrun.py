import asyncio
import base64
import json
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

import kaleido.fieldrun as fr
from kaleido.field import FieldMaterial, parse_field_material
from kaleido.phonepath import AddressVerifier, Connector, RelayConfig, RelayStats
from kaleido.runtime import EventBus, RuntimeConfig

_NOW = datetime(2026, 8, 14, 16, 0, 0, tzinfo=UTC)
_LOCAL_IPV4 = "10.23.0.2"
_EGRESS_IPV4 = "9.9.9.9"


def _certificate_pem() -> str:
    private_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kaleido-lab")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("kaleido-lab")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, algorithm=None)
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _material(*, psk: bytes = b"p" * 32, key_slot_id: str = "field-slot-01") -> FieldMaterial:
    identity = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    value = {
        "schema": "kaleido.field-material/v1",
        "endpoint_ipv4": "8.8.8.8",
        "port": 18443,
        "sni": "kaleido-lab",
        "psk_b64": base64.b64encode(psk).decode("ascii"),
        "server_identity_ed25519_b64": base64.b64encode(identity).decode("ascii"),
        "tls_certificate_pem": _certificate_pem(),
        "key_slot_id": key_slot_id,
        "issued_at_utc": (_NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (_NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }
    return parse_field_material(json.dumps(value).encode("utf-8"), now=lambda: _NOW)


def _settings(**overrides: object) -> fr.FieldRunSettings:
    values: dict[str, object] = {
        "interface_index": 20,
        "path_type": "usb_tether_phone_underlay_wifi",
        "expected_key_slot_id": "field-slot-01",
        "operator_ref": "OP-M01",
        "asn_ref": "AS-M01",
        "evidence_retained": False,
        "egress_hostname": "api.ipify.org",
        "attempt_id": "attempt-001",
        "phase_timeout": 0.5,
        "cleanup_timeout": 0.5,
        "discovery_timeout": 0.5,
    }
    values.update(overrides)
    return fr.FieldRunSettings(**values)  # type: ignore[arg-type]


def _relay_stats(*, verified: int = 2, cleanup_failures: int = 0) -> RelayStats:
    return RelayStats(
        accepted=2,
        rejected=0,
        completed=2,
        failed=0,
        cancelled=0,
        internal_failures=0,
        interface_verified=verified,
        bytes_client_to_target=100,
        bytes_target_to_client=100,
        cleanup_failures=cleanup_failures,
        active=0,
        pending_cleanup=0,
    )


class _DirectWriter:
    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.order.append("direct.close")

    async def wait_closed(self) -> None:
        self.order.append("direct.wait_closed")


class _FakeBus:
    def __init__(self, name: str, order: list[str]) -> None:
        self.name = name
        self.order = order
        self.records: list[dict[str, object]] = []
        self.total_dropped = 0

    async def start(self) -> None:
        self.order.append(f"{self.name}.bus.start")

    async def emit(self, event: dict[str, object]) -> None:
        self.records.append(dict(event))

    async def stop(self) -> None:
        self.order.append(f"{self.name}.bus.stop")


class _FakeRelay:
    def __init__(
        self,
        order: list[str],
        *,
        verified: int = 2,
        stop_fails: bool = False,
    ) -> None:
        self.order = order
        self.listen_port = 28443
        self.verified = verified
        self.stop_fails = stop_fails
        self.pending_cleanup = 0
        self.failed = 0
        self.internal_failures = 0

    @property
    def stats(self) -> RelayStats:
        stats = _relay_stats(verified=self.verified)
        return RelayStats(
            accepted=stats.accepted,
            rejected=stats.rejected,
            completed=stats.completed,
            failed=self.failed,
            cancelled=stats.cancelled,
            internal_failures=self.internal_failures,
            interface_verified=stats.interface_verified,
            bytes_client_to_target=stats.bytes_client_to_target,
            bytes_target_to_client=stats.bytes_target_to_client,
            cleanup_failures=stats.cleanup_failures,
            active=stats.active,
            pending_cleanup=self.pending_cleanup,
        )

    async def start(self) -> None:
        self.order.append("relay.start")

    async def wait_idle(self, *, timeout: float | None = None) -> None:
        assert timeout is not None and timeout > 0
        self.order.append("relay.idle")

    async def stop(self) -> None:
        self.order.append("relay.stop")
        if self.stop_fails:
            raise RuntimeError("relay stop detail must be sanitized")


class _FakeCarrier:
    def __init__(
        self,
        name: str,
        bus: _FakeBus,
        order: list[str],
        *,
        resistant_stop: bool,
        release: asyncio.Event,
    ) -> None:
        self.name = name
        self.bus = bus
        self.order = order
        self.socks_port = 31001 if name == "negative" else 31002
        self.resistant_stop = resistant_stop
        self.release = release

    async def start(self) -> None:
        self.order.append(f"{self.name}.carrier.start")

    async def stop(self) -> None:
        self.order.append(f"{self.name}.carrier.stop")
        if self.resistant_stop:
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                await self.release.wait()


class _Scenario:
    def __init__(self, material: FieldMaterial) -> None:
        self.material = material
        self.order: list[str] = []
        self.buses: list[_FakeBus] = []
        self.carriers: dict[int, _FakeCarrier] = {}
        self.configs: list[RuntimeConfig] = []
        self.relay = _FakeRelay(self.order)
        self.selected_local = _LOCAL_IPV4
        self.negative_events = ("carrier.connect", "auth.failed", "session.end")
        self.positive_events = (
            "carrier.connect",
            "auth.success",
            "dial.ok",
            "session.end",
        )
        self.negative_observation = fr.RequestObservation(False, None, None)
        self.positive_observation = fr.RequestObservation(True, 200, _EGRESS_IPV4)
        self.drop_negative_events = False
        self.reuse_bus = False
        self.resistant_request = False
        self.resistant_negative_stop = False
        self.release_request = asyncio.Event()
        self.release_stop = asyncio.Event()
        self.relay_config: RelayConfig | None = None
        self.verifier: AddressVerifier | None = None

    def discover(self, interface_index: int) -> str:
        assert interface_index == 20
        self.order.append("discover")
        return _LOCAL_IPV4

    async def connect(
        self,
        host: str,
        port: int,
        interface_index: int,
        timeout: float,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        assert host == self.material.endpoint_ipv4
        assert port == 18443
        assert interface_index == 20
        assert timeout > 0
        self.order.append("direct.connect")
        writer = _DirectWriter(self.order)
        return asyncio.StreamReader(), cast(asyncio.StreamWriter, writer), self.selected_local

    def relay_factory(
        self,
        config: RelayConfig,
        verifier: AddressVerifier,
        connector: Connector,
    ) -> _FakeRelay:
        assert connector == self.connect
        assert config.max_sessions == 1
        assert config.interface_index == 20
        assert config.target_host == self.material.endpoint_ipv4
        assert config.target_port == 18443
        self.relay_config = config
        self.verifier = verifier
        self.order.append("relay.factory")
        return self.relay

    def bus_factory(self) -> EventBus:
        name = "negative" if not self.buses else "positive"
        self.order.append(f"{name}.bus.factory")
        if self.reuse_bus and self.buses:
            return cast(EventBus, self.buses[0])
        bus = _FakeBus(name, self.order)
        self.buses.append(bus)
        return cast(EventBus, bus)

    def carrier_factory(
        self,
        config: RuntimeConfig,
        context: ssl.SSLContext,
        events: EventBus,
        endpoint: tuple[str, int, str],
    ) -> _FakeCarrier:
        del context
        assert endpoint == (fr.LOOPBACK_HOST, self.relay.listen_port, "kaleido-lab")
        positive = config.auth_secret == self.material.psk
        name = "positive" if positive else "negative"
        assert config.protocol_mode == "kal1"
        assert config.kal1_server_identity_public is self.material.server_identity_public
        assert config.socks_listen_host == fr.LOOPBACK_HOST
        assert config.socks_listen_port == 0
        assert config.insecure_outer_tls_for_lab is False
        assert config.max_outer_sessions == 1
        assert config.max_socks_sessions == 1
        if positive:
            assert config.auth_secret == self.material.psk
        else:
            assert config.auth_secret is not None
            assert len(config.auth_secret) == 32
            assert config.auth_secret != self.material.psk
        self.configs.append(config)
        self.order.append(f"{name}.carrier.factory")
        bus = cast(_FakeBus, events)
        carrier = _FakeCarrier(
            name,
            bus,
            self.order,
            resistant_stop=self.resistant_negative_stop and not positive,
            release=self.release_stop,
        )
        self.carriers[carrier.socks_port] = carrier
        return carrier

    async def request(
        self,
        socks_port: int,
        hostname: str,
        positive: bool,
    ) -> fr.RequestObservation:
        assert hostname == "api.ipify.org"
        carrier = self.carriers[socks_port]
        expected_name = "positive" if positive else "negative"
        assert carrier.name == expected_name
        self.order.append(f"{expected_name}.request")
        if positive and self.resistant_request:
            try:
                await self.release_request.wait()
            except asyncio.CancelledError:
                await self.release_request.wait()
        events = self.positive_events if positive else self.negative_events
        for event_type in events:
            await carrier.bus.emit({"type": event_type, "role": "client"})
        if not positive and self.drop_negative_events:
            carrier.bus.total_dropped = 1
            await carrier.bus.emit({"type": "eventbus.dropped", "count": 1})
        return self.positive_observation if positive else self.negative_observation

    def dependencies(self) -> fr.FieldRunDependencies:
        return fr.FieldRunDependencies(
            discover_interface=self.discover,
            connector=self.connect,
            relay_factory=self.relay_factory,
            event_bus_factory=self.bus_factory,
            carrier_factory=self.carrier_factory,
            request_executor=self.request,
            outer_tls_context_factory=lambda _material: ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            ),
            utc_now=lambda: _NOW,
        )


@pytest.mark.asyncio
async def test_success_orders_controls_and_uses_isolated_buses() -> None:
    material = _material()
    scenario = _Scenario(material)

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.cleanup_ok is True
    assert result.pending_cleanup == 0
    assert scenario.order == [
        "discover",
        "direct.connect",
        "direct.close",
        "direct.wait_closed",
        "relay.factory",
        "relay.start",
        "negative.bus.factory",
        "negative.bus.start",
        "negative.carrier.factory",
        "negative.carrier.start",
        "negative.request",
        "negative.carrier.stop",
        "negative.bus.stop",
        "relay.idle",
        "positive.bus.factory",
        "positive.bus.start",
        "positive.carrier.factory",
        "positive.carrier.start",
        "positive.request",
        "positive.carrier.stop",
        "positive.bus.stop",
        "relay.idle",
        "relay.stop",
    ]
    assert len(scenario.buses) == 2
    assert scenario.buses[0] is not scenario.buses[1]
    assert scenario.verifier is not None
    assert scenario.verifier(_LOCAL_IPV4) is True
    assert scenario.verifier("10.23.0.3") is False
    assert [record["case"] for record in result.records] == ["BADPSK", "HS"]
    assert [record["attempt_outcome"] for record in result.records] == ["pass", "pass"]
    assert result.records[0]["egress_scope"] == "not_attempted"
    assert result.records[1]["egress_scope"] == "configured_path"
    assert len(result.to_json_lines().splitlines()) == 2


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("interface_index", 0, "fresh positive integer"),
        ("interface_index", True, "fresh positive integer"),
        ("path_type", "usb_tether", "explicitly identify"),
        ("expected_key_slot_id", "unsafe slot", "safe opaque token"),
        ("operator_ref", "operator-one", "OP- reference"),
        ("asn_ref", "asn-one", "AS- reference"),
        ("evidence_retained", 1, "must be a boolean"),
        ("egress_hostname", "localhost", "public DNS hostname"),
        ("egress_hostname", "API.IPIFY.ORG", "public DNS hostname"),
        ("egress_hostname", "192.0.2.1", "public DNS hostname"),
        ("egress_hostname", "host.example", "public DNS hostname"),
        ("attempt_id", "unsafe attempt", "safe local token"),
        ("phase_timeout", 0.0, "finite and bounded"),
        ("cleanup_timeout", float("nan"), "finite and bounded"),
    ],
)
def test_settings_validation_is_strict(key: str, value: object, message: str) -> None:
    with pytest.raises(fr.FieldRunError, match=message):
        _settings(**{key: value})


def test_settings_and_private_results_have_redacted_repr() -> None:
    settings = _settings(egress_hostname="secret-sentinel.example.com")
    observation = fr.RequestObservation(True, 200, _EGRESS_IPV4)
    dependencies = fr.FieldRunDependencies()

    assert repr(settings) == "FieldRunSettings(<redacted>)"
    assert repr(observation) == "RequestObservation(<redacted>)"
    assert repr(dependencies) == "FieldRunDependencies(<redacted>)"
    assert "secret-sentinel" not in repr(settings)
    assert _EGRESS_IPV4 not in repr(observation)


@pytest.mark.asyncio
async def test_expected_key_slot_must_match_before_any_action() -> None:
    material = _material()
    scenario = _Scenario(material)

    with pytest.raises(fr.FieldRunError, match="does not match local expectation") as captured:
        await fr.run_field_attempt(
            material,
            _settings(expected_key_slot_id="other-local-slot"),
            dependencies=scenario.dependencies(),
        )

    assert scenario.order == []
    assert material.key_slot_id not in str(captured.value)


@pytest.mark.asyncio
async def test_badpsk_failure_blocks_positive_case() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.negative_events = ("auth.success", "dial.ok")
    scenario.negative_observation = fr.RequestObservation(True, None, None)

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.records[0]["attempt_outcome"] == "fail"
    assert result.records[0]["error_code"] == "badpsk_control_failed"
    assert result.records[1]["attempt_outcome"] == "inconclusive"
    assert result.records[1]["error_code"] == "badpsk_prerequisite_failed"
    assert "positive.carrier.factory" not in scenario.order
    assert "positive.request" not in scenario.order


@pytest.mark.asyncio
async def test_event_drops_invalidate_negative_evidence() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.drop_negative_events = True

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.records[0]["attempt_outcome"] == "inconclusive"
    assert result.records[0]["error_code"] == "event_evidence_dropped"
    assert "positive.request" not in scenario.order


@pytest.mark.asyncio
async def test_reused_event_bus_is_rejected() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.reuse_bus = True

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.records[0]["attempt_outcome"] == "pass"
    assert result.records[1]["attempt_outcome"] == "inconclusive"
    assert result.records[1]["error_code"] == "event_bus_not_isolated"


@pytest.mark.asyncio
async def test_positive_client_events_must_be_ordered() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.positive_events = ("dial.ok", "auth.success", "session.end")

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.records[1]["attempt_outcome"] == "fail"
    assert result.records[1]["error_code"] == "positive_socks_failed"


@pytest.mark.asyncio
async def test_auth_event_must_have_client_role() -> None:
    material = _material()
    scenario = _Scenario(material)

    async def wrong_role_request(
        socks_port: int,
        _hostname: str,
        positive: bool,
    ) -> fr.RequestObservation:
        assert positive is False
        carrier = scenario.carriers[socks_port]
        await carrier.bus.emit({"type": "auth.failed", "role": "server"})
        await carrier.bus.emit({"type": "session.end", "role": "client"})
        return fr.RequestObservation(False, None, None)

    dependencies = scenario.dependencies()
    dependencies = fr.FieldRunDependencies(
        discover_interface=dependencies.discover_interface,
        connector=dependencies.connector,
        relay_factory=dependencies.relay_factory,
        event_bus_factory=dependencies.event_bus_factory,
        carrier_factory=dependencies.carrier_factory,
        request_executor=wrong_role_request,
        outer_tls_context_factory=dependencies.outer_tls_context_factory,
        utc_now=dependencies.utc_now,
    )

    result = await fr.run_field_attempt(material, _settings(), dependencies=dependencies)

    assert result.records[0]["attempt_outcome"] == "fail"
    assert result.records[0]["error_code"] == "badpsk_control_failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("positive_events", "observation", "stage", "code"),
    [
        (
            ("auth.success", "session.end"),
            fr.RequestObservation(True, 200, _EGRESS_IPV4),
            "socks",
            "positive_socks_failed",
        ),
        (
            ("auth.success", "dial.ok", "session.end"),
            fr.RequestObservation(True, 503, _EGRESS_IPV4),
            "payload",
            "https_egress_failed",
        ),
        (
            ("auth.success", "dial.ok", "session.end"),
            fr.RequestObservation(True, 200, "192.0.2.1"),
            "payload",
            "https_egress_failed",
        ),
    ],
)
async def test_positive_requires_events_https_200_and_global_egress(
    positive_events: tuple[str, ...],
    observation: fr.RequestObservation,
    stage: str,
    code: str,
) -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.positive_events = positive_events
    scenario.positive_observation = observation

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.records[1]["attempt_outcome"] == "fail"
    assert result.records[1]["failure_stage"] == stage
    assert result.records[1]["error_code"] == code
    assert result.records[1]["egress_scope"] == "not_attempted"


@pytest.mark.asyncio
async def test_interface_source_mismatch_stops_before_relay() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.selected_local = "10.23.0.3"

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.exit_code == 1
    assert result.records[0]["error_code"] == "interface_source_mismatch"
    assert result.records[1]["error_code"] == "interface_source_mismatch"
    assert "direct.close" in scenario.order
    assert "relay.factory" not in scenario.order
    assert scenario.selected_local not in result.to_json_lines()


@pytest.mark.asyncio
async def test_cancellation_resistant_request_is_retained_and_reported() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.resistant_request = True

    result = await fr.run_field_attempt(
        material,
        _settings(phase_timeout=0.01, cleanup_timeout=0.05),
        dependencies=scenario.dependencies(),
    )

    assert result.exit_code == 1
    assert result.cleanup_ok is False
    assert result.pending_cleanup >= 1
    assert all(record["attempt_outcome"] == "inconclusive" for record in result.records)
    assert all(record["error_code"] == "cleanup_incomplete" for record in result.records)
    scenario.release_request.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_cancellation_resistant_cleanup_is_retained_and_reported() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.resistant_negative_stop = True

    result = await fr.run_field_attempt(
        material,
        _settings(cleanup_timeout=0.01),
        dependencies=scenario.dependencies(),
    )

    assert result.exit_code == 1
    assert result.cleanup_ok is False
    assert result.pending_cleanup >= 1
    assert all(record["attempt_outcome"] == "inconclusive" for record in result.records)
    scenario.release_stop.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_cleanup_exception_forces_inconclusive_nonzero() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.relay.stop_fails = True

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.exit_code == 1
    assert result.cleanup_ok is False
    assert result.pending_cleanup == 0
    assert all(record["attempt_outcome"] == "inconclusive" for record in result.records)
    assert all(record["error_code"] == "cleanup_incomplete" for record in result.records)


@pytest.mark.asyncio
async def test_relay_owned_pending_cleanup_is_reported() -> None:
    material = _material()
    scenario = _Scenario(material)
    scenario.relay.pending_cleanup = 3

    result = await fr.run_field_attempt(
        material,
        _settings(),
        dependencies=scenario.dependencies(),
    )

    assert result.cleanup_ok is False
    assert result.pending_cleanup == 3
    assert all(record["pending_cleanup"] == 3 for record in result.records)
    assert all(record["attempt_outcome"] == "inconclusive" for record in result.records)


@pytest.mark.asyncio
async def test_attempt_records_are_allowlisted_and_do_not_leak_material() -> None:
    sentinel = b"SENTINEL_SECRET_DO_NOT_DISCLOSE!"  # noqa: S105
    material = _material(psk=sentinel)
    scenario = _Scenario(material)
    scenario.positive_observation = fr.RequestObservation(True, 200, _EGRESS_IPV4)
    settings = _settings(egress_hostname="secret-sentinel.example.com")

    async def private_request(
        socks_port: int,
        hostname: str,
        positive: bool,
    ) -> fr.RequestObservation:
        assert hostname == "secret-sentinel.example.com"
        carrier = scenario.carriers[socks_port]
        events = scenario.positive_events if positive else scenario.negative_events
        for event_type in events:
            await carrier.bus.emit({"type": event_type, "role": "client"})
        return scenario.positive_observation if positive else scenario.negative_observation

    dependencies = scenario.dependencies()
    dependencies = fr.FieldRunDependencies(
        discover_interface=dependencies.discover_interface,
        connector=dependencies.connector,
        relay_factory=dependencies.relay_factory,
        event_bus_factory=dependencies.event_bus_factory,
        carrier_factory=dependencies.carrier_factory,
        request_executor=private_request,
        outer_tls_context_factory=dependencies.outer_tls_context_factory,
        utc_now=dependencies.utc_now,
    )

    result = await fr.run_field_attempt(material, settings, dependencies=dependencies)
    rendered = result.to_json_lines()

    assert repr(result) == "FieldRunResult(<redacted>)"
    assert all(set(record) == fr.ATTEMPT_RECORD_KEYS for record in result.records)
    assert sentinel.decode("ascii") not in rendered
    assert base64.b64encode(sentinel).decode("ascii") not in rendered
    assert material.endpoint_ipv4 not in rendered
    assert material.tls_certificate_pem not in rendered
    assert _LOCAL_IPV4 not in rendered
    assert _EGRESS_IPV4 not in rendered
    assert "secret-sentinel.example.com" not in rendered
    forbidden_keys = {
        "endpoint",
        "local_ip",
        "egress_ip",
        "destination",
        "psk",
        "private_key",
        "certificate",
        "ssid",
        "device_serial",
    }

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            assert not (forbidden_keys & value.keys())
            for nested in value.values():
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)

    for record in result.records:
        inspect(record)


def test_interface_discovery_is_read_only_hidden_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fr.sys, "platform", "win32")
    seen: dict[str, object] = {}

    def runner(command: tuple[str, ...], timeout: float) -> bytes:
        seen["command"] = command
        seen["timeout"] = timeout
        return _LOCAL_IPV4.encode("ascii")

    result = fr.discover_interface_ipv4(20, runner=runner, timeout=1.5)

    assert result == _LOCAL_IPV4
    command = cast(tuple[str, ...], seen["command"])
    assert "-NoProfile" in command
    assert "-NonInteractive" in command
    assert "-WindowStyle" in command
    assert "Hidden" in command
    assert "Get-NetIPAddress" in command[-1]
    assert "InterfaceIndex 20" in command[-1]
    assert seen["timeout"] == 1.5


def test_interface_discovery_sanitizes_errors_and_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fr.sys, "platform", "win32")
    sentinel = "SENTINEL_INTERFACE_DETAIL"

    def failing_runner(_command: tuple[str, ...], _timeout: float) -> bytes:
        raise fr.FieldRunError(f"{sentinel} {_LOCAL_IPV4}")

    with pytest.raises(fr.FieldRunError) as captured:
        fr.discover_interface_ipv4(20, runner=failing_runner)
    assert sentinel not in str(captured.value)
    assert _LOCAL_IPV4 not in str(captured.value)

    with pytest.raises(fr.FieldRunError, match="output is invalid"):
        fr.discover_interface_ipv4(
            20,
            runner=lambda _command, _timeout: b"x" * (fr.MAX_INTERFACE_OUTPUT_BYTES + 1),
        )


def test_interface_discovery_rejects_non_windows_without_running_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fr.sys, "platform", "linux")
    called = False

    def runner(_command: tuple[str, ...], _timeout: float) -> bytes:
        nonlocal called
        called = True
        return _LOCAL_IPV4.encode("ascii")

    with pytest.raises(fr.FieldRunError, match="requires Windows"):
        fr.discover_interface_ipv4(20, runner=runner)
    assert called is False


def test_default_powershell_runner_suppresses_stdin_stderr_and_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fr.sys, "platform", "win32")
    seen: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen["command"] = command
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=_LOCAL_IPV4.encode("ascii"))

    monkeypatch.setattr(fr.subprocess, "run", fake_run)

    assert fr.discover_interface_ipv4(20) == _LOCAL_IPV4
    assert seen["check"] is False
    assert seen["stdin"] == subprocess.DEVNULL
    assert seen["stdout"] == subprocess.PIPE
    assert seen["stderr"] == subprocess.DEVNULL
    assert seen["timeout"] == 5.0
    assert int(cast(int, seen["creationflags"])) != 0


@pytest.mark.asyncio
async def test_socks_https_request_uses_one_async_connection_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = asyncio.StreamReader()
    response = (
        b"\x05\x00"
        + b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.1.1.1"
    )
    reader.feed_data(response)
    reader.feed_eof()

    class Writer:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.tls_hostname: str | None = None
            self.closed = False

        def write(self, data: bytes) -> None:
            self.writes.append(data)

        async def drain(self) -> None:
            return None

        async def start_tls(
            self,
            _context: ssl.SSLContext,
            *,
            server_hostname: str | None = None,
            ssl_handshake_timeout: float | None = None,
        ) -> None:
            del ssl_handshake_timeout
            self.tls_hostname = server_hostname

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = Writer()
    calls = 0

    async def open_connection(
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        nonlocal calls
        calls += 1
        assert host == fr.LOOPBACK_HOST
        assert port == 31002
        return reader, cast(asyncio.StreamWriter, writer)

    monkeypatch.setattr(fr.asyncio, "open_connection", open_connection)

    observation = await fr.socks_https_request(31002, "api.ipify.org", True)

    assert calls == 1
    assert observation.socks_connected is True
    assert observation.https_status == 200
    assert observation.egress_ip == "1.1.1.1"
    assert writer.tls_hostname == "api.ipify.org"
    assert writer.closed is True
    assert len(writer.writes) == 3
