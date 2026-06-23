"""Optional, authorization-gated ACTIVE probing for cisbench.

cisbench is **passive and offline by default**: it scores a configuration
snapshot you provide. Nothing in the default path ever touches a live system.

This module adds a strictly-bounded *optional* active mode whose only job is to
**read** configuration evidence from a host you are explicitly authorized to
assess, normalise it into the very same inventory snapshot the passive engine
consumes, and hand it back. The active path is deliberately hemmed in by four
independent guardrails, all of which must be satisfied:

1. **Authorization flag.** Nothing runs unless ``authorized=True`` is passed
   (the CLI surfaces this as ``--authorized``). The default is always off.
2. **Target allowlist.** The host being probed must appear in an explicit
   allowlist supplied by the operator (``--allow``/``--allow-file``). A target
   that is not on the allowlist is refused before any socket is opened.
3. **Rate limiter.** A token-bucket limiter caps probe attempts per second so
   the tool cannot be turned into a sweeper/flooder.
4. **Read-only probes only.** The built-in probe performs a TCP connect and an
   optional banner read. It sends **no** authentication, **no** exploit
   payloads, and **no** state-changing traffic. It cannot log in, cannot bypass
   auth, and cannot modify the target.

The probe result is *evidence*, not a score: it is merged into an inventory
dict and then evaluated by the ordinary passive engine, so active and passive
runs are scored identically and reproducibly.

CI and unit tests exercise this module only against ``127.0.0.1`` / ``localhost``
or in-process fixtures — never a real external host.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

# Default read-only probe budget. Conservative on purpose.
DEFAULT_RATE_PER_SEC = 2.0
DEFAULT_TIMEOUT = 3.0
DEFAULT_BANNER_BYTES = 256


class ActiveError(RuntimeError):
    """Raised when an active probe is refused or fails its guardrails."""


class NotAuthorizedError(ActiveError):
    """Raised when active probing is attempted without explicit authorization."""


class TargetNotAllowedError(ActiveError):
    """Raised when a target is not present in the operator allowlist."""


# --------------------------------------------------------------------------- #
# rate limiter (token bucket)
# --------------------------------------------------------------------------- #
@dataclass
class RateLimiter:
    """A simple monotonic token-bucket rate limiter.

    ``rate`` tokens are added per second up to ``capacity``. ``acquire`` blocks
    (cooperatively, via the injected ``sleep``) until a token is available. The
    injectable clock/sleep keep it fully testable without real time passing.
    """

    rate: float = DEFAULT_RATE_PER_SEC
    capacity: float = DEFAULT_RATE_PER_SEC
    _tokens: float = field(default=0.0, init=False)
    _last: float = field(default=0.0, init=False)
    clock: Callable[[], float] = field(default=time.monotonic)
    sleep: Callable[[float], None] = field(default=time.sleep)

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be positive")
        if self.capacity <= 0:
            self.capacity = self.rate
        self._tokens = self.capacity
        self._last = self.clock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def try_acquire(self) -> bool:
        """Non-blocking: consume a token if available, else return False."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while not self.try_acquire():
            deficit = 1.0 - self._tokens
            wait = deficit / self.rate if self.rate else 0.05
            self.sleep(max(wait, 0.0))


# --------------------------------------------------------------------------- #
# target allowlist
# --------------------------------------------------------------------------- #
@dataclass
class Allowlist:
    """Explicit set of hosts an operator has authorized for active probing.

    Entries may be hostnames or IP literals. Matching is exact on the
    host token (case-insensitive for hostnames). No wildcard/CIDR expansion is
    performed by default — the operator must name each host — which keeps the
    blast radius small and auditable.
    """

    entries: set[str] = field(default_factory=set)

    @classmethod
    def from_iterable(cls, items: Iterable[str]) -> "Allowlist":
        norm = {i.strip().lower() for i in items if i and i.strip()}
        return cls(entries=norm)

    @classmethod
    def from_file(cls, path: str | Path) -> "Allowlist":
        p = Path(path)
        if not p.is_file():
            raise ActiveError(f"allowlist file not found: {p}")
        lines = []
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
        return cls.from_iterable(lines)

    def __len__(self) -> int:
        return len(self.entries)

    def allows(self, host: str) -> bool:
        return host.strip().lower() in self.entries


def is_loopback(host: str) -> bool:
    """True if the host is a loopback name or address (CI-safe targets)."""
    h = host.strip().lower()
    if h in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# probe target + result
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProbeTarget:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not self.host:
            raise ActiveError("probe target requires a host")
        if not (0 < self.port < 65536):
            raise ActiveError(f"invalid port {self.port}")


@dataclass
class ProbeResult:
    """Read-only evidence gathered from a single target."""

    target: ProbeTarget
    reachable: bool
    banner: str = ""
    latency_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.target.host,
            "port": self.target.port,
            "reachable": self.reachable,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
        }

    def to_inventory(self) -> dict[str, Any]:
        """Normalise the read-only evidence into an inventory fragment.

        Only *observed* facts are recorded. We never infer settings we did not
        actually read; absent evidence stays absent so the passive engine's
        conservative "missing -> FAIL" behaviour applies.
        """
        net: dict[str, Any] = {"reachable": self.reachable}
        inv: dict[str, Any] = {
            "_active_probe": self.to_dict(),
            "network": net,
        }
        return inv


# Signature of a probe function: (target, timeout) -> ProbeResult.
ProbeFn = Callable[[ProbeTarget, float], ProbeResult]


def tcp_banner_probe(target: ProbeTarget,
                     timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Read-only TCP connectivity + banner probe.

    Opens a TCP connection, optionally reads up to ``DEFAULT_BANNER_BYTES`` of
    any server-sent banner, and closes. It transmits nothing. This is purely an
    observation: no authentication, no payload, no state change.
    """
    start = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target.host, target.port),
                                        timeout=timeout)
        sock.settimeout(min(timeout, 1.0))
        banner = b""
        try:
            banner = sock.recv(DEFAULT_BANNER_BYTES)
        except (socket.timeout, OSError):
            banner = b""  # many DBs speak first only after a client hello
        latency = (time.monotonic() - start) * 1000.0
        return ProbeResult(
            target=target,
            reachable=True,
            banner=banner.decode("utf-8", "replace").strip(),
            latency_ms=latency,
        )
    except OSError as exc:
        latency = (time.monotonic() - start) * 1000.0
        return ProbeResult(target=target, reachable=False,
                           latency_ms=latency, error=str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover - defensive
                pass


@dataclass
class ActiveScanner:
    """Authorization-gated, rate-limited, read-only active probe driver.

    All four guardrails are enforced here:
      * ``authorized`` must be True;
      * every target must be in ``allowlist``;
      * a ``RateLimiter`` paces probe attempts;
      * the injected ``probe_fn`` is read-only (default: TCP banner grab).
    """

    authorized: bool = False
    allowlist: Allowlist = field(default_factory=Allowlist)
    limiter: RateLimiter = field(default_factory=RateLimiter)
    probe_fn: ProbeFn = tcp_banner_probe
    timeout: float = DEFAULT_TIMEOUT

    def _guard(self, target: ProbeTarget) -> None:
        if not self.authorized:
            raise NotAuthorizedError(
                "active probing is disabled; pass --authorized and an explicit "
                "target allowlist to enable read-only probing of hosts you are "
                "authorized to assess")
        if not self.allowlist.allows(target.host):
            raise TargetNotAllowedError(
                f"target {target.host!r} is not in the authorization "
                f"allowlist; add it explicitly to probe it")

    def probe(self, target: ProbeTarget) -> ProbeResult:
        """Probe a single allowlisted target after all guardrails pass."""
        self._guard(target)
        self.limiter.acquire()
        return self.probe_fn(target, self.timeout)

    def probe_all(self, targets: Iterable[ProbeTarget]) -> list[ProbeResult]:
        return [self.probe(t) for t in targets]


def merge_evidence(base: dict[str, Any],
                   results: Iterable[ProbeResult]) -> dict[str, Any]:
    """Deep-merge probe evidence into a base inventory (probe wins on leaves)."""
    out: dict[str, Any] = dict(base)
    probes = []
    for res in results:
        frag = res.to_inventory()
        probes.append(frag.pop("_active_probe"))
        _deep_merge(out, frag)
    if probes:
        out.setdefault("_active_probes", []).extend(probes)
    return out


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, val in src.items():
        if (key in dst and isinstance(dst[key], dict)
                and isinstance(val, dict)):
            _deep_merge(dst[key], val)
        else:
            dst[key] = val


def parse_target(spec: str, default_port: int = 5432) -> ProbeTarget:
    """Parse ``host[:port]`` into a ProbeTarget."""
    spec = spec.strip()
    if spec.startswith("[") and "]" in spec:  # bracketed IPv6
        host, _, rest = spec[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":") else default_port
        return ProbeTarget(host=host, port=port)
    if spec.count(":") == 1:
        host, _, port_s = spec.partition(":")
        return ProbeTarget(host=host, port=int(port_s) if port_s else default_port)
    return ProbeTarget(host=spec, port=default_port)
