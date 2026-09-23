import io
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import kaleido.cli as cli
from kaleido.cli import main


def test_score_cli(tmp_path, capsys) -> None:
    path = tmp_path / "observations.json"
    path.write_text(
        json.dumps(
            [
                {
                    "carrier": "tls",
                    "carrier_class": "tls-stream",
                    "success": True,
                    "handshake_ms": 100,
                    "goodput_mbps": 10,
                    "observed_at": 1_000,
                }
            ]
        ),
        encoding="utf-8",
    )

    assert main(["score", str(path), "--now", "1000"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output[0]["carrier"] == "tls"


def test_score_cli_rejects_non_array(tmp_path, capsys) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")

    assert main(["score", str(path)]) == 2
    assert "JSON array" in capsys.readouterr().err


def _write_lab_client(path: Path, *, insecure: bool) -> None:
    (path.parent / "psk.bin").write_bytes(b"p" * 32)
    path.write_text(
        json.dumps(
            {
                "schema": "kaleido.runtime/v1",
                "role": "client",
                "server": {"host": "vpn.example", "port": 443, "sni": "vpn.example"},
                "socks": {"host": "127.0.0.1", "port": 1080},
                "tls": {"insecure_lab": insecure},
                "protocol": {"mode": "lab", "psk_file": "psk.bin"},
            }
        ),
        encoding="utf-8",
    )


def _write_kal_server(path: Path) -> None:
    (path.parent / "psk.bin").write_bytes(b"p" * 32)
    identity = Ed25519PrivateKey.generate()
    (path.parent / "identity.pem").write_bytes(
        identity.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (path.parent / "cert.pem").write_text("cert", encoding="ascii")
    (path.parent / "tls-key.pem").write_text("key", encoding="ascii")
    path.write_text(
        json.dumps(
            {
                "schema": "kaleido.runtime/v1",
                "role": "server",
                "listen": {"host": "127.0.0.1", "port": 0},
                "tls": {
                    "certificate_file": "cert.pem",
                    "private_key_file": "tls-key.pem",
                },
                "protocol": {
                    "mode": "kal1",
                    "psk_file": "psk.bin",
                    "server_identity_private_file": "identity.pem",
                },
            }
        ),
        encoding="utf-8",
    )


def test_validate_cli_prints_only_non_secret_summary(tmp_path, capsys) -> None:
    path = tmp_path / "server.json"
    _write_kal_server(path)

    assert main(["validate", "--config", str(path)]) == 0
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "schema": "kaleido.runtime/v1",
        "role": "server",
        "protocol": "kal1",
        "valid": True,
    }
    assert "pppp" not in output


def test_keygen_cli_prints_paths_and_fingerprint_only(tmp_path, capsys) -> None:
    output = tmp_path / "keys"

    assert main(["keygen", "--output", str(output)]) == 0

    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"files", "server_identity_fingerprint"}
    assert len(data["files"]) == 3
    assert data["server_identity_fingerprint"].startswith("SHA256:")


def test_field_export_writes_envelope_only_to_binary_stdout(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "server.json"
    endpoint = object()
    output = io.BytesIO()
    calls: list[tuple[object, str, str, int]] = []

    def fake_load_config(config_path, *, expected_role=None):
        assert config_path == path
        assert expected_role == "server"
        return endpoint

    def fake_build(
        value, *, endpoint_ipv4, key_slot_id, lifetime_seconds
    ) -> bytes:
        calls.append((value, endpoint_ipv4, key_slot_id, lifetime_seconds))
        return b'{"schema":"synthetic"}'

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli, "build_field_material_envelope", fake_build)

    assert (
        cli._export_field_material(
            path,
            endpoint_ipv4="8.8.8.8",
            key_slot_id="KS-LAB-DE",
            lifetime_seconds=120,
            output=output,
        )
        == 0
    )
    assert output.getvalue() == b'{"schema":"synthetic"}\n'
    assert calls == [(endpoint, "8.8.8.8", "KS-LAB-DE", 120)]


def test_field_export_cli_dispatches_without_secret_arguments(tmp_path) -> None:
    path = tmp_path / "server.json"
    with patch("kaleido.cli._export_field_material", return_value=0) as export:
        assert (
            main(
                [
                    "field-export-material",
                    "--config",
                    str(path),
                    "--endpoint-ipv4",
                    "8.8.8.8",
                    "--key-slot-id",
                    "KS-LAB-DE",
                    "--lifetime-seconds",
                    "120",
                ]
            )
            == 0
        )
    export.assert_called_once_with(
        path,
        endpoint_ipv4="8.8.8.8",
        key_slot_id="KS-LAB-DE",
        lifetime_seconds=120,
    )


def test_field_export_refuses_interactive_stdout_before_loading_material(
    tmp_path, capsys
) -> None:
    path = tmp_path / "server.json"
    with (
        patch.object(cli.sys.stdout, "isatty", return_value=True),
        patch("kaleido.cli.load_config") as load,
    ):
        assert (
            main(
                [
                    "field-export-material",
                    "--config",
                    str(path),
                    "--endpoint-ipv4",
                    "8.8.8.8",
                    "--key-slot-id",
                    "KS-LAB-DE",
                ]
            )
            == 2
        )
    load.assert_not_called()
    assert "requires redirected stdout" in capsys.readouterr().err


def test_client_launch_lab_protocol_requires_gate(tmp_path, capsys) -> None:
    path = tmp_path / "client.json"
    _write_lab_client(path, insecure=False)

    assert main(["client", "--config", str(path)]) == 2
    assert "--allow-lab-protocol" in capsys.readouterr().err


def test_client_launch_insecure_tls_is_double_gated(tmp_path, capsys) -> None:
    path = tmp_path / "client.json"
    _write_lab_client(path, insecure=True)

    assert (
        main(["client", "--config", str(path), "--allow-lab-protocol"])
        == 2
    )
    assert "both --allow-lab-protocol and --allow-insecure-lab" in capsys.readouterr().err


def test_launch_uses_one_endpoint_coroutine_and_warns(tmp_path, capsys) -> None:
    path = tmp_path / "client.json"
    _write_lab_client(path, insecure=False)

    with patch("kaleido.cli._serve_endpoint", new=AsyncMock()) as serve:
        assert (
            main(["client", "--config", str(path), "--allow-lab-protocol"])
            == 0
        )

    serve.assert_awaited_once()
    assert "research prototype" in capsys.readouterr().err
