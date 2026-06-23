"""Tests for the optional, authorization-gated active probe layer.

Every test here is bounded to 127.0.0.1 / localhost or an in-process fake
probe. No test ever opens a socket to an external host. The guardrails
(authorization, allowlist, rate limiter, read-only) are each exercised
directly.
"""

import socket
import threading

import pytest

from cisbench.active import (
    ActiveError,
    ActiveScanner,
    Allowlist,
    NotAuthorizedError,
    ProbeResult,
    ProbeTarget,
    RateLimiter,
    TargetNotAllowedError,
    is_loopback,
    merge_evidence,
    parse_target,
    tcp_banner_probe,
)


# --------------------------------------------------------------------------- #
# rate limiter
# --------------------------------------------------------------------------- #
class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept += s
        self.t += s


def test_rate_limiter_starts_full():
    rl = RateLimiter(rate=2.0, capacity=2.0)
    assert rl.try_acquire() is True
    assert rl.try_acquire() is True


def test_rate_limiter_blocks_when_empty():
    clk = FakeClock()
    rl = RateLimiter(rate=2.0, capacity=2.0, clock=clk.now, sleep=clk.sleep)
    assert rl.try_acquire() is True
    assert rl.try_acquire() is True
    # bucket now empty
    assert rl.try_acquire() is False


def test_rate_limiter_refills_over_time():
    clk = FakeClock()
    rl = RateLimiter(rate=2.0, capacity=2.0, clock=clk.now, sleep=clk.sleep)
    rl.try_acquire(); rl.try_acquire()
    assert rl.try_acquire() is False
    clk.t += 0.5  # 0.5s * 2/s = 1 token
    assert rl.try_acquire() is True


def test_rate_limiter_acquire_sleeps_until_token():
    clk = FakeClock()
    rl = RateLimiter(rate=4.0, capacity=1.0, clock=clk.now, sleep=clk.sleep)
    rl.acquire()           # consumes the initial token, no sleep
    rl.acquire()           # must wait for a refill
    assert clk.slept > 0.0


def test_rate_limiter_rejects_nonpositive_rate():
    with pytest.raises(ValueError):
        RateLimiter(rate=0.0)


# --------------------------------------------------------------------------- #
# allowlist
# --------------------------------------------------------------------------- #
def test_allowlist_exact_match_case_insensitive():
    al = Allowlist.from_iterable(["DB.internal", "127.0.0.1"])
    assert al.allows("db.internal")
    assert al.allows("127.0.0.1")
    assert not al.allows("evil.example.com")


def test_allowlist_len_and_empty():
    assert len(Allowlist.from_iterable([])) == 0
    assert len(Allowlist.from_iterable(["a", "b", "a"])) == 2


def test_allowlist_from_file(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_text("# hosts\nlocalhost\n127.0.0.1\n\n# comment\n",
                 encoding="utf-8")
    al = Allowlist.from_file(p)
    assert al.allows("localhost")
    assert al.allows("127.0.0.1")
    assert len(al) == 2


def test_allowlist_from_missing_file_raises():
    with pytest.raises(ActiveError):
        Allowlist.from_file("does-not-exist-allow.txt")


# --------------------------------------------------------------------------- #
# loopback detection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host,expected", [
    ("localhost", True),
    ("127.0.0.1", True),
    ("127.5.5.5", True),
    ("::1", True),
    ("10.0.0.5", False),
    ("example.com", False),
])
def test_is_loopback(host, expected):
    assert is_loopback(host) is expected


# --------------------------------------------------------------------------- #
# probe target parsing
# --------------------------------------------------------------------------- #
def test_parse_target_with_port():
    t = parse_target("localhost:5433")
    assert t.host == "localhost" and t.port == 5433


def test_parse_target_default_port():
    t = parse_target("localhost", default_port=3306)
    assert t.port == 3306


def test_parse_target_ipv6_bracketed():
    t = parse_target("[::1]:5432")
    assert t.host == "::1" and t.port == 5432


def test_probe_target_rejects_bad_port():
    with pytest.raises(ActiveError):
        ProbeTarget(host="localhost", port=0)
    with pytest.raises(ActiveError):
        ProbeTarget(host="localhost", port=99999)


def test_probe_target_rejects_empty_host():
    with pytest.raises(ActiveError):
        ProbeTarget(host="", port=5432)


# --------------------------------------------------------------------------- #
# guardrails on the scanner
# --------------------------------------------------------------------------- #
def _fake_probe(target, timeout):
    return ProbeResult(target=target, reachable=True, banner="FAKE")


def test_scanner_refuses_without_authorization():
    sc = ActiveScanner(authorized=False,
                       allowlist=Allowlist.from_iterable(["localhost"]),
                       probe_fn=_fake_probe)
    with pytest.raises(NotAuthorizedError):
        sc.probe(ProbeTarget("localhost", 5432))


def test_scanner_refuses_target_not_in_allowlist():
    sc = ActiveScanner(authorized=True,
                       allowlist=Allowlist.from_iterable(["localhost"]),
                       probe_fn=_fake_probe)
    with pytest.raises(TargetNotAllowedError):
        sc.probe(ProbeTarget("10.0.0.9", 5432))


def test_scanner_allows_authorized_allowlisted_target():
    sc = ActiveScanner(authorized=True,
                       allowlist=Allowlist.from_iterable(["localhost"]),
                       probe_fn=_fake_probe)
    res = sc.probe(ProbeTarget("localhost", 5432))
    assert res.reachable is True
    assert res.banner == "FAKE"


def test_scanner_rate_limited_probe_all():
    clk = FakeClock()
    sc = ActiveScanner(
        authorized=True,
        allowlist=Allowlist.from_iterable(["localhost"]),
        limiter=RateLimiter(rate=10.0, capacity=1.0,
                            clock=clk.now, sleep=clk.sleep),
        probe_fn=_fake_probe,
    )
    targets = [ProbeTarget("localhost", 5432) for _ in range(3)]
    results = sc.probe_all(targets)
    assert len(results) == 3
    # capacity 1 -> the 2nd and 3rd probes had to wait for refills
    assert clk.slept > 0.0


# --------------------------------------------------------------------------- #
# read-only TCP banner probe against a localhost listener
# --------------------------------------------------------------------------- #
@pytest.fixture
def local_banner_server():
    """A localhost TCP server that sends a banner then closes. CI-safe."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = {"bytes": b""}

    def serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(0.5)
            try:
                # Record anything the probe sends (should be nothing).
                received["bytes"] = conn.recv(64)
            except (socket.timeout, OSError):
                pass
            conn.sendall(b"PostgreSQL 15.0 ready\n")
            conn.close()
        except OSError:
            pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield port, received
    srv.close()
    th.join(timeout=1.0)


def test_tcp_banner_probe_reads_banner(local_banner_server):
    port, _ = local_banner_server
    res = tcp_banner_probe(ProbeTarget("127.0.0.1", port), timeout=2.0)
    assert res.reachable is True
    assert "PostgreSQL" in res.banner
    assert res.error == ""


def test_tcp_banner_probe_is_read_only_sends_nothing(local_banner_server):
    port, received = local_banner_server
    tcp_banner_probe(ProbeTarget("127.0.0.1", port), timeout=2.0)
    # the probe must transmit nothing to the target
    assert received["bytes"] == b""


def test_tcp_banner_probe_unreachable_port():
    # Port 1 on loopback is almost certainly closed; connect should fail fast.
    res = tcp_banner_probe(ProbeTarget("127.0.0.1", 1), timeout=1.0)
    assert res.reachable is False
    assert res.error


def test_scanner_end_to_end_against_localhost(local_banner_server):
    port, _ = local_banner_server
    sc = ActiveScanner(authorized=True,
                       allowlist=Allowlist.from_iterable(["127.0.0.1"]))
    res = sc.probe(ProbeTarget("127.0.0.1", port))
    assert res.reachable is True
    assert "PostgreSQL" in res.banner


# --------------------------------------------------------------------------- #
# evidence merging into an inventory
# --------------------------------------------------------------------------- #
def test_probe_result_to_inventory_records_reachability():
    res = ProbeResult(target=ProbeTarget("localhost", 5432), reachable=True)
    inv = res.to_inventory()
    assert inv["network"]["reachable"] is True
    assert inv["_active_probe"]["host"] == "localhost"


def test_merge_evidence_deep_merges_and_records_probes():
    base = {"network": {"require_tls": True}, "auth": {"password_min_length": 16}}
    res = ProbeResult(target=ProbeTarget("localhost", 5432), reachable=True,
                      banner="x")
    merged = merge_evidence(base, [res])
    # base settings preserved
    assert merged["network"]["require_tls"] is True
    assert merged["auth"]["password_min_length"] == 16
    # probe evidence merged in
    assert merged["network"]["reachable"] is True
    assert len(merged["_active_probes"]) == 1
    assert merged["_active_probes"][0]["banner"] == "x"


def test_merge_evidence_only_records_observed_facts():
    """The probe must not invent settings it did not actually read."""
    res = ProbeResult(target=ProbeTarget("localhost", 5432), reachable=False)
    merged = merge_evidence({}, [res])
    # only reachability is asserted; nothing else fabricated
    assert set(merged["network"].keys()) == {"reachable"}
    assert merged["network"]["reachable"] is False
