"""Diskless, fail-closed parsing of short-lived field material."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import BinaryIO, Final, NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA: Final = "kaleido.field-material/v1"
OUTER_TLS_PORT: Final = 18443
OUTER_TLS_SERVER_NAME: Final = "kaleido-lab"
MAX_ENVELOPE_BYTES: Final = 64 * 1024
MAX_CERTIFICATE_PEM_BYTES: Final = 48 * 1024
MAX_MATERIAL_LIFETIME: Final = timedelta(minutes=15)
MAX_FUTURE_CLOCK_SKEW: Final = timedelta(seconds=60)

_ENVELOPE_KEYS: Final = frozenset(
    {
        "schema",
        "endpoint_ipv4",
        "port",
        "sni",
        "psk_b64",
        "server_identity_ed25519_b64",
        "tls_certificate_pem",
        "key_slot_id",
        "issued_at_utc",
        "expires_at_utc",
    }
)
_OPAQUE_SLOT_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UTC_TIMESTAMP_RE: Final = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z"
)
_PEM_CERTIFICATE_RE: Final = re.compile(
    rb"\A-----BEGIN CERTIFICATE-----\r?\n"
    rb"(?:[A-Za-z0-9+/]{1,76}={0,2}\r?\n)+"
    rb"-----END CERTIFICATE-----\r?\n?\Z"
)

Clock = Callable[[], datetime]


class FieldMaterialError(ValueError):
    """The field-material envelope violates a fixed safety invariant."""


@dataclass(frozen=True, slots=True, repr=False)
class FieldMaterial:
    """Validated short-lived material retained only in process memory."""

    endpoint_ipv4: str = field(repr=False)
    port: int = field(repr=False)
    sni: str = field(repr=False)
    psk: bytes = field(repr=False)
    server_identity_public: Ed25519PublicKey = field(repr=False)
    tls_certificate: x509.Certificate = field(repr=False)
    tls_certificate_pem: str = field(repr=False)
    key_slot_id: str = field(repr=False)
    issued_at_utc: datetime = field(repr=False)
    expires_at_utc: datetime = field(repr=False)

    def __repr__(self) -> str:
        """Return a deliberately value-free representation."""

        return "FieldMaterial(<redacted>)"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FieldMaterialError("field envelope contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise FieldMaterialError("field envelope is not strict JSON")


def _string(root: dict[str, object], key: str, error: str) -> str:
    value = root[key]
    if not isinstance(value, str):
        raise FieldMaterialError(error)
    return value


def _strict_base64(value: object, *, label: str) -> bytes:
    error = f"{label} must be canonical base64"
    if not isinstance(value, str) or not value.isascii():
        raise FieldMaterialError(error)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise FieldMaterialError(error) from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FieldMaterialError(error)
    return decoded


def _parse_endpoint(value: object) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise FieldMaterialError("endpoint_ipv4 must be a globally routable numeric IPv4 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise FieldMaterialError(
            "endpoint_ipv4 must be a globally routable numeric IPv4 address"
        ) from None
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_global
        or address.is_multicast
        or address.is_reserved
        or str(address) != value
    ):
        raise FieldMaterialError("endpoint_ipv4 must be a globally routable numeric IPv4 address")
    return value


def _parse_timestamp(value: object, *, label: str) -> datetime:
    error = f"{label} must be an ISO 8601 UTC timestamp"
    if not isinstance(value, str) or _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise FieldMaterialError(error)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise FieldMaterialError(error) from None
    if parsed.utcoffset() != timedelta(0):
        raise FieldMaterialError(error)
    return parsed.astimezone(UTC)


def _parse_certificate(value: object) -> tuple[x509.Certificate, str]:
    error = "tls_certificate_pem must contain exactly one PEM X.509 certificate"
    if not isinstance(value, str):
        raise FieldMaterialError(error)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise FieldMaterialError(error) from None
    if (
        not encoded
        or len(encoded) > MAX_CERTIFICATE_PEM_BYTES
        or _PEM_CERTIFICATE_RE.fullmatch(encoded) is None
    ):
        raise FieldMaterialError(error)
    try:
        certificates = x509.load_pem_x509_certificates(encoded)
    except ValueError:
        raise FieldMaterialError(error) from None
    if len(certificates) != 1:
        raise FieldMaterialError(error)
    certificate = certificates[0]
    try:
        extensions = certificate.extensions
    except Exception:
        raise FieldMaterialError(error) from None
    try:
        constraints = extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise FieldMaterialError(
            "TLS certificate must declare end-entity BasicConstraints"
        ) from None
    if constraints.ca:
        raise FieldMaterialError("TLS certificate must be an end-entity certificate")
    try:
        key_usage = extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and key_usage.key_cert_sign:
        raise FieldMaterialError("TLS certificate must not authorize certificate signing")
    return certificate, value


def _current_time(clock: Clock) -> datetime:
    try:
        current = clock()
    except Exception:
        raise FieldMaterialError("field-material clock failed") from None
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise FieldMaterialError("field-material clock must return a UTC datetime")
    try:
        offset = current.utcoffset()
    except Exception:
        raise FieldMaterialError("field-material clock must return a UTC datetime") from None
    if offset != timedelta(0):
        raise FieldMaterialError("field-material clock must return a UTC datetime")
    return current.astimezone(UTC)


def parse_field_material(data: bytes, *, now: Clock = _utc_now) -> FieldMaterial:
    """Parse and validate one bounded JSON field-material envelope."""

    if not isinstance(data, bytes):
        raise FieldMaterialError("field envelope must be bytes")
    if not data or len(data) > MAX_ENVELOPE_BYTES:
        raise FieldMaterialError("field envelope size is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FieldMaterialError("field envelope must be UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except FieldMaterialError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise FieldMaterialError("field envelope is not valid JSON") from None
    if not isinstance(value, dict):
        raise FieldMaterialError("field envelope must be a JSON object")
    root = cast(dict[str, object], value)
    if set(root) != _ENVELOPE_KEYS:
        raise FieldMaterialError("field envelope keys do not match the schema")
    if root["schema"] != SCHEMA:
        raise FieldMaterialError("field envelope schema is unsupported")

    endpoint = _parse_endpoint(root["endpoint_ipv4"])
    port = root["port"]
    if not isinstance(port, int) or isinstance(port, bool) or port != OUTER_TLS_PORT:
        raise FieldMaterialError("port must be 18443")
    sni = _string(root, "sni", "sni must be kaleido-lab")
    if sni != OUTER_TLS_SERVER_NAME:
        raise FieldMaterialError("sni must be kaleido-lab")

    psk = _strict_base64(root["psk_b64"], label="psk_b64")
    if len(psk) != 32:
        raise FieldMaterialError("psk_b64 must decode to exactly 32 bytes")
    identity_bytes = _strict_base64(
        root["server_identity_ed25519_b64"], label="server_identity_ed25519_b64"
    )
    if len(identity_bytes) != 32:
        raise FieldMaterialError(
            "server_identity_ed25519_b64 must decode to exactly 32 bytes"
        )
    try:
        identity = Ed25519PublicKey.from_public_bytes(identity_bytes)
    except ValueError:
        raise FieldMaterialError("server identity public key is invalid") from None

    certificate, certificate_pem = _parse_certificate(root["tls_certificate_pem"])
    key_slot_id = _string(root, "key_slot_id", "key_slot_id must be an opaque token")
    if _OPAQUE_SLOT_RE.fullmatch(key_slot_id) is None:
        raise FieldMaterialError("key_slot_id must be an opaque token")

    issued_at = _parse_timestamp(root["issued_at_utc"], label="issued_at_utc")
    expires_at = _parse_timestamp(root["expires_at_utc"], label="expires_at_utc")
    current = _current_time(now)
    if expires_at <= issued_at:
        raise FieldMaterialError("field-material validity interval is invalid")
    if expires_at - issued_at > MAX_MATERIAL_LIFETIME:
        raise FieldMaterialError("field-material lifetime exceeds 15 minutes")
    if issued_at > current and issued_at - current > MAX_FUTURE_CLOCK_SKEW:
        raise FieldMaterialError("field material was issued too far in the future")
    if expires_at <= current:
        raise FieldMaterialError("field material is expired")

    return FieldMaterial(
        endpoint_ipv4=endpoint,
        port=port,
        sni=sni,
        psk=psk,
        server_identity_public=identity,
        tls_certificate=certificate,
        tls_certificate_pem=certificate_pem,
        key_slot_id=key_slot_id,
        issued_at_utc=issued_at,
        expires_at_utc=expires_at,
    )


def read_field_material(stream: BinaryIO, *, now: Clock = _utc_now) -> FieldMaterial:
    """Read at most one bounded envelope from a binary stdin-like stream."""

    chunks: list[bytes] = []
    remaining = MAX_ENVELOPE_BYTES + 1
    while remaining > 0:
        try:
            chunk = stream.read(remaining)
        except Exception:
            raise FieldMaterialError("cannot read field envelope") from None
        if not isinstance(chunk, bytes):
            raise FieldMaterialError("field envelope stream must be binary")
        if len(chunk) > remaining:
            raise FieldMaterialError("field envelope size is invalid")
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return parse_field_material(data, now=now)


def build_outer_tls_context(material: FieldMaterial) -> ssl.SSLContext:
    """Create an exclusive leaf-trust TLS 1.3 client context in memory."""

    if not isinstance(material, FieldMaterial):
        raise FieldMaterialError("validated field material is required")
    partial_chain = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", None)
    if not ssl.HAS_TLSv1_3 or partial_chain is None:
        raise FieldMaterialError("required TLS 1.3 verification support is unavailable")
    _, certificate_pem = _parse_certificate(material.tls_certificate_pem)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.verify_flags |= partial_chain
    try:
        context.load_verify_locations(cadata=certificate_pem)
    except (ssl.SSLError, ValueError):
        raise FieldMaterialError("TLS certificate trust setup failed") from None
    store_stats = context.cert_store_stats()
    if store_stats["x509"] != 1 or store_stats["x509_ca"] != 0:
        raise FieldMaterialError("TLS certificate trust setup was not exclusive")
    return context


__all__ = [
    "MAX_ENVELOPE_BYTES",
    "MAX_FUTURE_CLOCK_SKEW",
    "MAX_MATERIAL_LIFETIME",
    "OUTER_TLS_PORT",
    "OUTER_TLS_SERVER_NAME",
    "SCHEMA",
    "FieldMaterial",
    "FieldMaterialError",
    "build_outer_tls_context",
    "parse_field_material",
    "read_field_material",
]
