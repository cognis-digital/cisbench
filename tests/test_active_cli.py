"""CLI tests for the optional active-scan subcommand.

All network activity is confined to 127.0.0.1 with an in-process listener.
The refusal-path tests open no sockets at all.
"""

import json
import socket
import threading

import pytest

from cisbench.cli import main


# --------------------------------------------------------------------------- #
# refusal paths (no sockets opened)
# --------------------------------------------------------------------------- #
def test_active_scan_off_by_default(capsys):
    rc = main(["active-scan", "127.0.0.1:5432", "--allow", "127.0.0.1"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "OFF by default" in err
    assert "--authorized" in err


def test_active_scan_authorized_requires_allowlist(capsys):
    rc = main(["active-scan", "127.0.0.1:5432", "--authorized"])
    assert rc == 2
    assert "non-empty target allowlist" in capsys.readouterr().err


def test_active_scan_refuses_target_not_in_allowlist(capsys):
    rc = main(["active-scan", "10.0.0.9:5432",
               "--authorized", "--allow", "127.0.0.1"])
    assert rc == 2
    assert "not in the authorization allowlist" in capsys.readouterr().err


def test_active_scan_allow_file(tmp_path, capsys):
    p = tmp_path / "allow.txt"
    p.write_text("127.0.0.1\n", encoding="utf-8")
    # Target not in file -> refused even with --authorized.
    rc = main(["active-scan", "192.0.2.1:5432",
               "--authorized", "--allow-file", str(p)])
    assert rc == 2
    assert "not in the authorization allowlist" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# end-to-end against a localhost listener
# --------------------------------------------------------------------------- #
@pytest.fixture
def local_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"db-ready\n")
            conn.close()
        except OSError:
            pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield port
    srv.close()
    th.join(timeout=1.0)


def test_active_scan_emit_inventory(local_server, capsys):
    rc = main(["active-scan", f"127.0.0.1:{local_server}",
               "--authorized", "--allow", "127.0.0.1",
               "--emit-inventory"])
    assert rc == 0
    inv = json.loads(capsys.readouterr().out)
    assert inv["network"]["reachable"] is True
    assert inv["_active_probes"][0]["port"] == local_server


def test_active_scan_merges_base_inventory_and_scores(local_server, tmp_path,
                                                      capsys):
    # A base inventory that is fully hardened; the probe only adds reachability.
    base = {
        "network": {"require_tls": True, "min_tls_version": 1.3,
                    "bind_address": "10.0.0.5"},
        "auth": {"password_min_length": 16, "password_complexity_enabled": True,
                 "failed_login_lockout_threshold": 5,
                 "anonymous_login_enabled": False},
        "audit": {"logging_enabled": True, "retention_days": 365},
        "accounts": {"default_admin_renamed": True},
        "storage": {"encryption_at_rest": True},
        "diagnostics": {"verbose_client_errors": False},
    }
    bp = tmp_path / "base.json"
    bp.write_text(json.dumps(base), encoding="utf-8")
    rc = main(["active-scan", f"127.0.0.1:{local_server}",
               "--authorized", "--allow", "127.0.0.1",
               "--from", str(bp), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["score"] == 100.0
    assert data["active_probes"][0]["reachable"] is True


def test_active_scan_table_output(local_server, capsys):
    rc = main(["active-scan", f"127.0.0.1:{local_server}",
               "--authorized", "--allow", "127.0.0.1", "--no-color"])
    # No base inventory -> baseline checks fail (missing settings), so the
    # default exit code is still 0 (no gate set); output names the target.
    assert rc == 0
    out = capsys.readouterr().out
    assert "active-scan" in out
    assert "reachable" in out
    assert "127.0.0.1" in out


def test_active_scan_sarif(local_server, capsys):
    rc = main(["active-scan", f"127.0.0.1:{local_server}",
               "--authorized", "--allow", "127.0.0.1", "--sarif"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
