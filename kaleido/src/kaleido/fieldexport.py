"""Build a short-lived field-material envelope without exporting private keys."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

from cryptography.hazmat.primitives import serialization

from .config import EndpointConfig
from .field import (
    MAX_CERTIFICATE_PEM_BYTES,
    MAX_MATERIAL_LIFETIME,
    OUTER_TLS_PORT,
    OUTER_TLS_SERVER_NAME,
    SCHEMA,
    FieldMaterialError,
    parse_field_material,
)

DEFAULT_MATERIAL_LIFETIME_SECONDS: Final = 5 * 60
Clock = Callable[[], datetime]


class FieldExportError(ValueError):
    """The server cannot safely produce a field-material envelope."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _current_time(clock: Clock) -> datetime:
    try:
        current = clock()
        offset = current.utcoffset() if isinstance(current, datetime) else None
    except Exception:
        raise FieldExportError("field-material clock failed") from None
    if not isinstance(current, datetime) or current.tzinfo is None or offset != timedelta(0):
        raise FieldExportError("field-material clock must return a UTC datetime")
    return current.astimezone(UTC)


def _read_public_certificate(endpoint: EndpointConfig) -> str:
    path = endpoint.tls_certificate_file
    if path is None:
        raise FieldExportError("server TLS certificate is unavailable")
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_CERTIFICATE_PEM_BYTES + 1)
            if stream.read(1):
                raise FieldExportError("server TLS certificate is too large")
    except FieldExportError:
        raise
    except OSError:
        raise FieldExportError("cannot read server TLS certificate") from None
    if len(data) > MAX_CERTIFICATE_PEM_BYTES:
        raise FieldExportError("server TLS certificate is too large")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise FieldExportError("server TLS certificate is not PEM ASCII") from None


def build_field_material_envelope(
    endpoint: EndpointConfig,
    *,
    endpoint_ipv4: str,
    key_slot_id: str,
    lifetime_seconds: int = DEFAULT_MATERIAL_LIFETIME_SECONDS,
    now: Clock = _utc_now,
) -> bytes:
    """Return one validated ASCII JSON envelope suitable only for an SSH pipe."""

    if endpoint.role != "server" or endpoint.runtime.protocol_mode != "kal1":
        raise FieldExportError("a validated KAL/1 server configuration is required")
    psk = endpoint.runtime.auth_secret
    identity_private = endpoint.runtime.kal1_server_identity_private
    if psk is None or len(psk) != 32 or identity_private is None:
        raise FieldExportError("server field material is incomplete")
    if (
        not isinstance(lifetime_seconds, int)
        or isinstance(lifetime_seconds, bool)
        or lifetime_seconds <= 0
        or timedelta(seconds=lifetime_seconds) > MAX_MATERIAL_LIFETIME
    ):
        raise FieldExportError("field-material lifetime must be 1..900 seconds")

    issued_at = _current_time(now).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=lifetime_seconds)
    identity_public = identity_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    certificate_pem = _read_public_certificate(endpoint)
    envelope = {
        "schema": SCHEMA,
        "endpoint_ipv4": endpoint_ipv4,
        "port": OUTER_TLS_PORT,
        "sni": OUTER_TLS_SERVER_NAME,
        "psk_b64": base64.b64encode(psk).decode("ascii"),
        "server_identity_ed25519_b64": base64.b64encode(identity_public).decode("ascii"),
        "tls_certificate_pem": certificate_pem,
        "key_slot_id": key_slot_id,
        "issued_at_utc": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": expires_at.isoformat().replace("+00:00", "Z"),
    }
    encoded = json.dumps(envelope, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    try:
        parse_field_material(encoded, now=lambda: issued_at)
    except FieldMaterialError:
        raise FieldExportError("generated field material failed validation") from None
    return encoded


__all__ = [
    "DEFAULT_MATERIAL_LIFETIME_SECONDS",
    "FieldExportError",
    "build_field_material_envelope",
]
