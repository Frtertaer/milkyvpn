import asyncio
import base64
import io
import json
import ssl
from datetime import UTC, datetime, timedelta
from typing import BinaryIO, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from kaleido.field import (
    MAX_ENVELOPE_BYTES,
    MAX_FUTURE_CLOCK_SKEW,
    MAX_MATERIAL_LIFETIME,
    OUTER_TLS_PORT,
    OUTER_TLS_SERVER_NAME,
    SCHEMA,
    FieldMaterialError,
    build_outer_tls_context,
    parse_field_material,
    read_field_material,
)

_NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=UTC)
_PUBLIC_ENDPOINT = "8.8.8.8"


def _certificate_pem(
    *,
    ca: bool = False,
    include_basic_constraints: bool = True,
    key_cert_sign: bool = False,
) -> str:
    private_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, OUTER_TLS_SERVER_NAME)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(OUTER_TLS_SERVER_NAME)]),
            critical=False,
        )
    )
    if include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=key_cert_sign,
            crl_sign=key_cert_sign,
            encipher_only=None,
            decipher_only=None,
        ),
        critical=True,
    )
    certificate = builder.sign(private_key, algorithm=None)
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _envelope(
    *,
    psk: bytes = b"p" * 32,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    identity = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    issued = issued_at or _NOW - timedelta(minutes=1)
    expires = expires_at or _NOW + timedelta(minutes=10)
    return {
        "schema": SCHEMA,
        "endpoint_ipv4": _PUBLIC_ENDPOINT,
        "port": OUTER_TLS_PORT,
        "sni": OUTER_TLS_SERVER_NAME,
        "psk_b64": base64.b64encode(psk).decode("ascii"),
        "server_identity_ed25519_b64": base64.b64encode(identity).decode("ascii"),
        "tls_certificate_pem": _certificate_pem(),
        "key_slot_id": "field-slot-01",
        "issued_at_utc": issued.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": expires.isoformat().replace("+00:00", "Z"),
    }


def _encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _parse(value: object):  # type: ignore[no-untyped-def]
    return parse_field_material(_encode(value), now=lambda: _NOW)


def test_parse_valid_envelope_returns_typed_redacted_material() -> None:
    value = _envelope()

    material = _parse(value)

    assert material.endpoint_ipv4 == _PUBLIC_ENDPOINT
    assert material.port == OUTER_TLS_PORT
    assert material.sni == OUTER_TLS_SERVER_NAME
    assert material.psk == b"p" * 32
    assert material.server_identity_public.public_bytes_raw() == base64.b64decode(
        cast(str, value["server_identity_ed25519_b64"]), validate=True
    )
    assert isinstance(material.tls_certificate, x509.Certificate)
    assert material.key_slot_id == "field-slot-01"
    assert repr(material) == "FieldMaterial(<redacted>)"


def test_duplicate_unknown_and_missing_keys_are_rejected() -> None:
    valid = _encode(_envelope())
    duplicate = valid.replace(
        b'{"schema":',
        b'{"schema":"kaleido.field-material/v1","schema":',
        1,
    )
    with pytest.raises(FieldMaterialError, match="duplicate key"):
        parse_field_material(duplicate, now=lambda: _NOW)

    unknown = _envelope()
    unknown["unexpected"] = True
    with pytest.raises(FieldMaterialError, match="keys do not match"):
        _parse(unknown)

    missing = _envelope()
    del missing["key_slot_id"]
    with pytest.raises(FieldMaterialError, match="keys do not match"):
        _parse(missing)


@pytest.mark.parametrize(
    "invalid",
    [
        "not-base64!!",
        base64.b64encode(b"p" * 32).decode("ascii").replace("c", "c\n", 1),
        base64.b64encode(b"p" * 32).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(b"\xff" * 32).decode("ascii"),
        base64.b64encode(b"\x00" * 32).decode("ascii")[:-2] + "B=",
        base64.b64encode(b"p" * 32).decode("ascii") + "=",
    ],
)
def test_psk_rejects_malformed_or_lenient_base64(invalid: str) -> None:
    value = _envelope()
    value["psk_b64"] = invalid

    with pytest.raises(FieldMaterialError, match="canonical base64"):
        _parse(value)


@pytest.mark.parametrize(
    ("field_name", "size"),
    [
        ("psk_b64", 31),
        ("psk_b64", 33),
        ("server_identity_ed25519_b64", 31),
        ("server_identity_ed25519_b64", 33),
    ],
)
def test_binary_keys_must_be_exactly_32_bytes(field_name: str, size: int) -> None:
    value = _envelope()
    value[field_name] = base64.b64encode(b"x" * size).decode("ascii")

    with pytest.raises(FieldMaterialError, match="exactly 32 bytes"):
        _parse(value)


@pytest.mark.parametrize(
    "certificate_value",
    [
        lambda pem: pem + pem,
        lambda pem: pem + "trailing-data",
        lambda pem: "\n" + pem,
        lambda pem: pem + "\n",
    ],
)
def test_certificate_rejects_multiple_certificates_and_trailing_data(
    certificate_value: object,
) -> None:
    value = _envelope()
    pem = cast(str, value["tls_certificate_pem"])
    value["tls_certificate_pem"] = certificate_value(pem)  # type: ignore[operator]

    with pytest.raises(FieldMaterialError, match="exactly one PEM X.509 certificate"):
        _parse(value)


def test_certificate_rejects_invalid_pem_body() -> None:
    value = _envelope()
    value["tls_certificate_pem"] = (
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    )

    with pytest.raises(FieldMaterialError, match="exactly one PEM X.509 certificate"):
        _parse(value)


def test_certificate_rejects_ca_trust_anchor() -> None:
    value = _envelope()
    value["tls_certificate_pem"] = _certificate_pem(ca=True)

    with pytest.raises(FieldMaterialError, match="end-entity certificate"):
        _parse(value)


def test_certificate_without_basic_constraints_cannot_become_ca_trust() -> None:
    value = _envelope()
    value["tls_certificate_pem"] = _certificate_pem(
        include_basic_constraints=False,
        key_cert_sign=True,
    )

    with pytest.raises(FieldMaterialError, match="end-entity BasicConstraints"):
        _parse(value)


def test_lazy_certificate_extension_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "MALFORMED_EXTENSION_SENTINEL"

    class MalformedCertificate:
        @property
        def extensions(self) -> x509.Extensions:
            raise ValueError(sentinel)

    def load_malformed(_data: bytes) -> list[x509.Certificate]:
        return [cast(x509.Certificate, MalformedCertificate())]

    monkeypatch.setattr(x509, "load_pem_x509_certificates", load_malformed)

    with pytest.raises(FieldMaterialError) as captured:
        _parse(_envelope())
    assert sentinel not in str(captured.value)


@pytest.mark.parametrize(
    "endpoint",
    ["localhost", "127.0.0.1", "10.0.0.1", "::1", "224.0.0.1", "8.8.8.08"],
)
def test_endpoint_must_be_canonical_global_numeric_ipv4(endpoint: str) -> None:
    value = _envelope()
    value["endpoint_ipv4"] = endpoint

    with pytest.raises(FieldMaterialError, match="globally routable numeric IPv4"):
        _parse(value)


@pytest.mark.parametrize("port", [443, "18443", True])
def test_port_is_fixed_and_integer(port: object) -> None:
    value = _envelope()
    value["port"] = port

    with pytest.raises(FieldMaterialError, match="port must be 18443"):
        _parse(value)


@pytest.mark.parametrize(
    "slot_id",
    ["contains whitespace", "unsafe/slash", 'unsafe"quote', "x" * 65],
)
def test_sni_and_key_slot_are_strict(slot_id: str) -> None:
    wrong_sni = _envelope()
    wrong_sni["sni"] = "example.test"
    with pytest.raises(FieldMaterialError, match="sni must be kaleido-lab"):
        _parse(wrong_sni)

    bad_slot = _envelope()
    bad_slot["key_slot_id"] = slot_id
    with pytest.raises(FieldMaterialError, match="opaque token"):
        _parse(bad_slot)


def test_timestamps_require_utc() -> None:
    value = _envelope()
    value["issued_at_utc"] = "2026-08-14T14:59:00+03:00"

    with pytest.raises(FieldMaterialError, match="UTC timestamp"):
        _parse(value)


def test_expired_and_invalid_intervals_are_rejected() -> None:
    expired = _envelope(
        issued_at=_NOW - timedelta(minutes=2),
        expires_at=_NOW - timedelta(microseconds=1),
    )
    with pytest.raises(FieldMaterialError, match="expired"):
        _parse(expired)

    at_expiry = _envelope(issued_at=_NOW - timedelta(minutes=1), expires_at=_NOW)
    with pytest.raises(FieldMaterialError, match="expired"):
        _parse(at_expiry)

    reversed_interval = _envelope(issued_at=_NOW, expires_at=_NOW)
    with pytest.raises(FieldMaterialError, match="validity interval"):
        _parse(reversed_interval)

    too_long = _envelope(
        issued_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW - timedelta(minutes=1) + MAX_MATERIAL_LIFETIME + timedelta(microseconds=1),
    )
    with pytest.raises(FieldMaterialError, match="lifetime exceeds"):
        _parse(too_long)


def test_max_lifetime_and_small_future_clock_skew_are_accepted() -> None:
    max_lifetime = _envelope(issued_at=_NOW, expires_at=_NOW + MAX_MATERIAL_LIFETIME)
    parsed = _parse(max_lifetime)
    assert parsed.expires_at_utc - parsed.issued_at_utc == MAX_MATERIAL_LIFETIME

    future = _envelope(
        issued_at=_NOW + MAX_FUTURE_CLOCK_SKEW,
        expires_at=_NOW + MAX_FUTURE_CLOCK_SKEW + timedelta(minutes=1),
    )
    assert _parse(future).issued_at_utc == _NOW + MAX_FUTURE_CLOCK_SKEW


def test_material_issued_beyond_clock_skew_is_rejected() -> None:
    value = _envelope(
        issued_at=_NOW + MAX_FUTURE_CLOCK_SKEW + timedelta(microseconds=1),
        expires_at=_NOW + MAX_FUTURE_CLOCK_SKEW + timedelta(minutes=1),
    )

    with pytest.raises(FieldMaterialError, match="too far in the future"):
        _parse(value)


def test_injected_clock_must_return_utc_datetime() -> None:
    data = _encode(_envelope())

    with pytest.raises(FieldMaterialError, match="clock must return a UTC datetime"):
        parse_field_material(data, now=lambda: datetime(2026, 8, 14, 12, 0, 0))


def test_binary_stream_read_is_bounded() -> None:
    valid = _encode(_envelope())
    assert read_field_material(io.BytesIO(valid), now=lambda: _NOW).port == OUTER_TLS_PORT

    with pytest.raises(FieldMaterialError, match="size is invalid"):
        read_field_material(io.BytesIO(b"x" * (MAX_ENVELOPE_BYTES + 1)), now=lambda: _NOW)


def test_binary_stream_short_reads_cannot_hide_trailing_data() -> None:
    class ChunkedStream:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks
            self.requests: list[int] = []

        def read(self, size: int = -1) -> bytes:
            self.requests.append(size)
            return self.chunks.pop(0) if self.chunks else b""

    stream = ChunkedStream([_encode(_envelope()), b"trailing-data"])

    with pytest.raises(FieldMaterialError, match="not valid JSON"):
        read_field_material(cast(BinaryIO, stream), now=lambda: _NOW)
    assert all(0 < request <= MAX_ENVELOPE_BYTES + 1 for request in stream.requests)


def test_text_stream_is_rejected() -> None:
    stream = cast(BinaryIO, io.StringIO("{}"))

    with pytest.raises(FieldMaterialError, match="stream must be binary"):
        read_field_material(stream, now=lambda: _NOW)


def test_outer_tls_context_is_tls13_verified_and_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _parse(_envelope())

    def fail_default_context(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("default/system trust must not be loaded")

    monkeypatch.setattr(ssl, "create_default_context", fail_default_context)
    context = build_outer_tls_context(material)

    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    assert context.cert_store_stats()["x509"] == 1
    assert context.cert_store_stats()["x509_ca"] == 0


@pytest.mark.asyncio
async def test_outer_tls_context_completes_tls13_with_pinned_leaf(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, OUTER_TLS_SERVER_NAME)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(OUTER_TLS_SERVER_NAME)]),
            critical=False,
        )
        .sign(private_key, algorithm=None)
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_path = tmp_path / "leaf.pem"
    key_path = tmp_path / "leaf-key.pem"
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    value = _envelope()
    value["tls_certificate_pem"] = certificate_pem.decode("ascii")
    context = build_outer_tls_context(_parse(value))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(str(certificate_path), str(key_path))

    async def close_client(
        _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(
        close_client,
        "127.0.0.1",
        0,
        ssl=server_context,
    )
    try:
        port = int(server.sockets[0].getsockname()[1])
        _reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=context,
            server_hostname=OUTER_TLS_SERVER_NAME,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        assert ssl_object is not None
        assert ssl_object.version() == "TLSv1.3"
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


def test_outer_tls_context_has_no_partial_chain_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _parse(_envelope())
    monkeypatch.delattr(ssl, "VERIFY_X509_PARTIAL_CHAIN")

    with pytest.raises(FieldMaterialError, match="verification support is unavailable"):
        build_outer_tls_context(material)


def test_secrets_never_appear_in_material_repr_or_errors() -> None:
    sentinel = b"SENTINEL_SECRET_DO_NOT_DISCLOSE!"  # noqa: S105
    encoded_sentinel = base64.b64encode(sentinel).decode("ascii")
    value = _envelope(psk=sentinel)
    material = _parse(value)

    representation = repr(material)
    assert sentinel.decode("ascii") not in representation
    assert encoded_sentinel not in representation

    malformed = _envelope()
    malformed["psk_b64"] = sentinel.decode("ascii")
    with pytest.raises(FieldMaterialError) as captured:
        _parse(malformed)
    rendered_error = f"{captured.value!s} {captured.value!r}"
    assert sentinel.decode("ascii") not in rendered_error
    assert encoded_sentinel not in rendered_error

    sentinel_key = _envelope()
    sentinel_key[sentinel.decode("ascii")] = "value"
    with pytest.raises(FieldMaterialError) as captured_key:
        _parse(sentinel_key)
    assert sentinel.decode("ascii") not in str(captured_key.value)


def test_nonstandard_json_constants_are_rejected() -> None:
    valid = _encode(_envelope())
    invalid = valid.replace(b'"port":18443', b'"port":NaN', 1)

    with pytest.raises(FieldMaterialError, match="strict JSON"):
        parse_field_material(invalid, now=lambda: _NOW)


def test_certificate_fingerprint_is_not_needed_for_trust_loading() -> None:
    material = _parse(_envelope())
    fingerprint = material.tls_certificate.fingerprint(hashes.SHA256())

    assert len(fingerprint) == hashes.SHA256().digest_size
