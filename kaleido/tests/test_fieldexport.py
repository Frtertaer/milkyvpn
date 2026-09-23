from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import NameOID

from kaleido.config import EndpointConfig
from kaleido.field import parse_field_material
from kaleido.fieldexport import FieldExportError, build_field_material_envelope
from kaleido.runtime import RuntimeConfig

_NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
_ENDPOINT = "8.8.8.8"


def _certificate() -> bytes:
    key = generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kaleido-lab")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW.replace(year=2025, tzinfo=None))
        .not_valid_after(_NOW.replace(year=2027, tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("kaleido-lab")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def _endpoint(tmp_path: Path) -> tuple[EndpointConfig, Ed25519PrivateKey, bytes]:
    certificate_path = tmp_path / "leaf.pem"
    certificate_path.write_bytes(_certificate())
    identity = Ed25519PrivateKey.generate()
    psk = bytes(range(32))
    endpoint = EndpointConfig(
        path=tmp_path / "server.json",
        role="server",
        runtime=RuntimeConfig(
            auth_secret=psk,
            protocol_mode="kal1",
            kal1_server_identity_private=identity,
        ),
        tls_certificate_file=certificate_path,
        tls_private_key_file=tmp_path / "private-key-never-read.pem",
    )
    return endpoint, identity, psk


def test_export_roundtrip_contains_only_required_public_material(tmp_path: Path) -> None:
    endpoint, identity, psk = _endpoint(tmp_path)
    encoded = build_field_material_envelope(
        endpoint,
        endpoint_ipv4=_ENDPOINT,
        key_slot_id="KS-LAB-DE",
        now=lambda: _NOW,
    )

    material = parse_field_material(encoded, now=lambda: _NOW)
    assert material.endpoint_ipv4 == _ENDPOINT
    assert material.psk == psk
    assert material.key_slot_id == "KS-LAB-DE"
    private_raw = identity.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert base64.b64encode(private_raw) not in encoded
    assert b"PRIVATE KEY" not in encoded
    assert b"private-key-never-read" not in encoded


@pytest.mark.parametrize("lifetime", [True, 0, -1, 901, 1.5])
def test_export_rejects_invalid_lifetime(tmp_path: Path, lifetime: object) -> None:
    endpoint, _identity, _psk = _endpoint(tmp_path)
    with pytest.raises(FieldExportError, match="lifetime"):
        build_field_material_envelope(
            endpoint,
            endpoint_ipv4=_ENDPOINT,
            key_slot_id="KS-LAB-DE",
            lifetime_seconds=lifetime,  # type: ignore[arg-type]
            now=lambda: _NOW,
        )


def test_export_rejects_non_server_without_material_detail(tmp_path: Path) -> None:
    endpoint, _identity, _psk = _endpoint(tmp_path)
    client = EndpointConfig(path=endpoint.path, role="client", runtime=endpoint.runtime)
    with pytest.raises(FieldExportError) as caught:
        build_field_material_envelope(
            client,
            endpoint_ipv4=_ENDPOINT,
            key_slot_id="KS-LAB-DE",
            now=lambda: _NOW,
        )
    assert "KS-LAB-DE" not in str(caught.value)


def test_export_sanitizes_certificate_read_failure(tmp_path: Path) -> None:
    endpoint, _identity, _psk = _endpoint(tmp_path)
    marker = "private-path-marker"
    missing = EndpointConfig(
        path=endpoint.path,
        role="server",
        runtime=endpoint.runtime,
        tls_certificate_file=tmp_path / marker,
    )
    with pytest.raises(FieldExportError) as caught:
        build_field_material_envelope(
            missing,
            endpoint_ipv4=_ENDPOINT,
            key_slot_id="KS-LAB-DE",
            now=lambda: _NOW,
        )
    assert marker not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    ("endpoint_ipv4", "key_slot_id"),
    [
        ("127.0.0.1", "KS-LAB-DE"),
        (_ENDPOINT, "bad slot"),
    ],
)
def test_export_self_validation_fails_closed(
    tmp_path: Path, endpoint_ipv4: str, key_slot_id: str
) -> None:
    endpoint, _identity, _psk = _endpoint(tmp_path)
    with pytest.raises(FieldExportError, match="generated field material failed validation"):
        build_field_material_envelope(
            endpoint,
            endpoint_ipv4=endpoint_ipv4,
            key_slot_id=key_slot_id,
            now=lambda: _NOW,
        )
