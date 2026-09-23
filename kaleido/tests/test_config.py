import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kaleido.config import MAX_CONFIG_BYTES, ConfigError, generate_keys, load_config


def _materials(directory: Path) -> None:
    directory.mkdir(exist_ok=True)
    (directory / "kaleido.psk").write_bytes(b"p" * 32)
    identity = Ed25519PrivateKey.generate()
    (directory / "server-identity-private.pem").write_bytes(
        identity.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / "server-identity-public.pem").write_bytes(
        identity.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (directory / "cert.pem").write_text("certificate fixture", encoding="ascii")
    (directory / "tls-key.pem").write_text("TLS key fixture", encoding="ascii")
    (directory / "ca.pem").write_text("CA fixture", encoding="ascii")


def _server_config() -> dict[str, object]:
    return {
        "schema": "kaleido.runtime/v1",
        "role": "server",
        "listen": {"host": "0.0.0.0", "port": 443},  # noqa: S104
        "tls": {"certificate_file": "cert.pem", "private_key_file": "tls-key.pem"},
        "protocol": {
            "mode": "kal1",
            "psk_file": "kaleido.psk",
            "server_identity_private_file": "server-identity-private.pem",
        },
    }


def _client_config() -> dict[str, object]:
    return {
        "schema": "kaleido.runtime/v1",
        "role": "client",
        "server": {"host": "vpn.example", "port": 443, "sni": "vpn.example"},
        "socks": {"host": "127.0.0.1", "port": 1080},
        "tls": {"ca_file": "ca.pem"},
        "protocol": {
            "mode": "kal1",
            "psk_file": "kaleido.psk",
            "server_identity_public_file": "server-identity-public.pem",
        },
    }


def _write_config(path: Path, value: object, *, encoding: str = "utf-8") -> None:
    path.write_text(json.dumps(value), encoding=encoding)


def test_server_config_accepts_bom_and_resolves_paths(tmp_path: Path) -> None:
    _materials(tmp_path)
    path = tmp_path / "server.json"
    _write_config(path, _server_config(), encoding="utf-8-sig")

    result = load_config(path, expected_role="server")

    assert result.role == "server"
    assert result.runtime.protocol_mode == "kal1"
    assert result.runtime.auth_secret == b"p" * 32
    assert result.runtime.kal1_server_identity_private is not None
    assert result.tls_certificate_file == tmp_path / "cert.pem"


def test_client_config_verifies_tls_by_default_and_is_loopback(tmp_path: Path) -> None:
    _materials(tmp_path)
    path = tmp_path / "client.json"
    _write_config(path, _client_config())

    result = load_config(path, expected_role="client")

    assert result.runtime.insecure_outer_tls_for_lab is False
    assert result.runtime.socks_listen_host == "127.0.0.1"
    assert result.runtime.kal1_server_identity_public is not None
    assert result.server_endpoint == ("vpn.example", 443, "vpn.example")


def test_socks_auth_requires_and_loads_username(tmp_path: Path) -> None:
    _materials(tmp_path)
    (tmp_path / "socks-password.bin").write_bytes(b"test-password-value")
    value = _client_config()
    value["socks_auth"] = {
        "required": True,
        "username": "kaleido",
        "secret_file": "socks-password.bin",
    }
    path = tmp_path / "client.json"
    _write_config(path, value)

    result = load_config(path)

    assert result.runtime.socks_auth_username == b"kaleido"
    assert result.runtime.socks_auth_secret == b"test-password-value"


def test_runtime_limits_and_socks_deadline_are_loaded(tmp_path: Path) -> None:
    _materials(tmp_path)
    value = _client_config()
    value["timeouts"] = {"socks_handshake_seconds": 2.5}
    value["limits"] = {"outer_sessions": 17, "socks_sessions": 9}
    path = tmp_path / "client.json"
    _write_config(path, value)

    result = load_config(path)

    assert result.runtime.socks_handshake_timeout == 2.5
    assert result.runtime.max_outer_sessions == 17
    assert result.runtime.max_socks_sessions == 9


@pytest.mark.parametrize(
    ("key", "value"),
    [("outer_sessions", 0), ("socks_sessions", 65536), ("socks_sessions", False)],
)
def test_runtime_limits_reject_unsafe_values(
    tmp_path: Path, key: str, value: object
) -> None:
    _materials(tmp_path)
    config = _server_config()
    config["limits"] = {key: value}
    path = tmp_path / "server.json"
    _write_config(path, config)

    with pytest.raises(ConfigError, match=f"limits.{key}"):
        load_config(path)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "localhost"])  # noqa: S104
def test_client_rejects_non_ip_or_non_loopback_socks(tmp_path: Path, host: str) -> None:
    _materials(tmp_path)
    value = _client_config()
    value["socks"] = {"host": host, "port": 1080}
    path = tmp_path / "client.json"
    _write_config(path, value)

    with pytest.raises(ConfigError, match="loopback"):
        load_config(path)


def test_unknown_and_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    _materials(tmp_path)
    unknown = _server_config()
    unknown["auth_secret"] = "must never be inline"  # noqa: S105
    unknown_path = tmp_path / "unknown.json"
    _write_config(unknown_path, unknown)

    with pytest.raises(ConfigError, match="unknown top-level"):
        load_config(unknown_path)

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        '{"schema":"kaleido.runtime/v1","schema":"other","role":"server"}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(duplicate_path)


def test_psk_is_exactly_32_binary_bytes(tmp_path: Path) -> None:
    _materials(tmp_path)
    (tmp_path / "kaleido.psk").write_bytes(b"a" * 31)
    path = tmp_path / "server.json"
    _write_config(path, _server_config())

    with pytest.raises(ConfigError, match="exactly 32 binary bytes"):
        load_config(path)


def test_rejects_wrong_identity_encoding(tmp_path: Path) -> None:
    _materials(tmp_path)
    (tmp_path / "server-identity-private.pem").write_bytes(b"not PKCS8")
    path = tmp_path / "server.json"
    _write_config(path, _server_config())

    with pytest.raises(ConfigError, match="PEM PKCS8"):
        load_config(path)


def test_rejects_large_config_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))

    with pytest.raises(ConfigError, match="exceeds"):
        load_config(path)


def test_insecure_tls_is_only_valid_with_lab_protocol(tmp_path: Path) -> None:
    _materials(tmp_path)
    value = _client_config()
    value["tls"] = {"insecure_lab": True}
    path = tmp_path / "client.json"
    _write_config(path, value)

    with pytest.raises(ConfigError, match="only with protocol.mode='lab'"):
        load_config(path)


def test_generate_keys_creates_binary_psk_and_typed_identity(tmp_path: Path) -> None:
    output = tmp_path / "new-keys"

    paths, fingerprint = generate_keys(output)

    assert paths[0].read_bytes().__len__() == 32
    private = serialization.load_pem_private_key(paths[1].read_bytes(), password=None)
    public = serialization.load_pem_public_key(paths[2].read_bytes())
    assert isinstance(private, Ed25519PrivateKey)
    assert fingerprint.startswith("SHA256:")
    assert private.public_key().public_bytes_raw() == public.public_bytes_raw()
    if os.name != "nt":
        assert paths[0].stat().st_mode & 0o077 == 0
        assert paths[1].stat().st_mode & 0o077 == 0


def test_generate_keys_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "keys"
    generate_keys(output)

    with pytest.raises(ConfigError, match="refusing to overwrite"):
        generate_keys(output)


def test_generate_keys_rejects_symlink_output(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ConfigError, match="symbolic links"):
        generate_keys(link)
