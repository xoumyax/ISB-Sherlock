"""HTTP for the collector: paced, retried, breaker-guarded, TLS always verified.

COLLECT §3.3. One request at a time, at least ``min_interval_s`` between requests
to the same host. 429/5xx and connection errors are retried (``Retry-After``
honoured, capped); 404/410 are final. Each host has a breaker: after
``breaker_consecutive_failures`` failed attempts in a row it is tripped. It is
half-open (review B2, 25 Nov): while it cools down (``breaker_cooldown_s``)
payload requests raise :class:`HostTripped` without touching the network, and
catalogue ``get`` sleeps the cooldown out (at most ``catalog_trip_waits`` times
per call) so planning survives a short outage; then one probe goes through, and
a good probe closes the breaker while a bad one re-trips it. The breaker counts
attempts, not requests, so a host answering 429 with a long ``Retry-After`` trips
within ``N`` attempts rather than after a day of sleeping.

Bodies have wall-clock deadlines (``download_deadline_s``, ``get_deadline_s``); a
declared Content-Length over ``max_bytes`` is refused before any body byte. URLs
and redirect targets with non-ASCII characters are percent-encoded (UTF-8); a
malformed one is refused; any unexpected exception in the real transport becomes
:class:`TransportError` (review B1).

TLS is verified with the default context. A TLS error is never retried and never
bypassed: there is no code path that turns verification off.

Redirects are followed here, hop by hop, never by the transport:

* catalogue fetches (:meth:`Fetcher.get`, the planners' Getter) stay on the
  allowlisted hosts given at construction; any hop off it is refused;
* payload downloads (:meth:`Fetcher.download`) may move to another https host,
  because the payload is checked against a catalogue digest afterwards;
* a redirect to plain http is always refused.

Every error a download raises carries ``bytes_read``: the body bytes of the final
response read before it failed, which the ledger needs to decide a refund. Retries
only happen before the first body byte.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "DEFAULT_CONFIG",
    "DownloadResult",
    "FetchError",
    "Fetcher",
    "HostTripped",
    "HttpConfig",
    "HttpStatusError",
    "MockResponse",
    "MockTransport",
    "RedirectRefused",
    "Response",
    "TlsError",
    "TooLarge",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "host_of",
]

_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class HttpConfig:
    #: Seconds between two requests to one host (the V1-era kit's value).
    min_interval_s: float = 1.0
    #: Socket timeout per request.
    timeout_s: float = 60.0
    #: Retries after the first attempt, for 429/5xx/connection errors.
    max_retries: int = 5
    #: Failed attempts in a row after which a host is tripped.
    breaker_consecutive_failures: int = 25
    #: Seconds a tripped host is left alone; then one probe is let through
    #: (half-open). A good probe closes the breaker, a bad one re-trips it.
    breaker_cooldown_s: float = 1800.0
    #: Cooldowns a catalogue ``get`` sleeps through before giving up, so planning
    #: (NuGet: ~8,000 calls) survives a short outage instead of failing.
    catalog_trip_waits: int = 3
    #: Wall-clock limit on one payload body / one catalogue body (seconds).
    download_deadline_s: float = 1800.0
    get_deadline_s: float = 600.0
    #: Longest honoured Retry-After; a server asking for more gets this.
    max_retry_after_s: float = 900.0
    #: Backoff without Retry-After: base * 2**attempt, capped.
    backoff_base_s: float = 2.0
    backoff_max_s: float = 120.0
    #: Redirect hops followed per request.
    max_redirects: int = 5
    #: Bytes per read while streaming.
    chunk_bytes: int = 1 << 20
    #: Generic; no names or contact details (privacy rule).
    user_agent: str = "research-goodware-collector/0.1 (python-urllib)"


DEFAULT_CONFIG = HttpConfig()


# -- errors -------------------------------------------------------------------


class FetchError(Exception):
    """Base for every fetch failure. ``reason`` is a short code for stats."""

    reason = "fetch_error"

    def __init__(self, message: str, *, bytes_read: int = 0) -> None:
        super().__init__(message)
        self.bytes_read = bytes_read


class TransportError(FetchError):
    """Connection reset, timeout, DNS failure: retried before the first byte."""

    reason = "connection_error"


class TlsError(FetchError):
    """Certificate or handshake failure: never retried, never bypassed."""

    reason = "tls_error"


class HttpStatusError(FetchError):
    reason = "http_status"

    def __init__(self, status: int, url: str, *, bytes_read: int = 0) -> None:
        super().__init__(f"HTTP {status} for {url}", bytes_read=bytes_read)
        self.status = status
        self.reason = f"http_{status}"


class HostTripped(FetchError):
    reason = "host_tripped"


class RedirectRefused(FetchError):
    reason = "redirect_refused"


class TooLarge(FetchError):
    reason = "too_large"


# -- transport ----------------------------------------------------------------


class Response(Protocol):
    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]:
        """Lower-cased header names."""
        ...

    @property
    def url(self) -> str: ...

    def read(self, n: int) -> bytes: ...

    def close(self) -> None: ...


class Transport(Protocol):
    def open(self, method: str, url: str, headers: Mapping[str, str]) -> Response:
        """One request, no redirect following. Raises TransportError/TlsError."""
        ...


def host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def _ascii_url(url: str) -> str:
    """Percent-encode non-ASCII (UTF-8), keeping URL delimiters and escapes."""
    if url.isascii():
        return url
    return urllib.parse.quote(url, safe="!#$%&'()*+,/:;=?@[]~")


def _is_tls(exc: object) -> bool:
    return isinstance(exc, ssl.SSLError | ssl.CertificateError)


class _UrllibResponse:
    def __init__(self, raw: Any, url: str) -> None:
        self._raw = raw
        self.status = int(raw.status if hasattr(raw, "status") else raw.code)
        self.headers = {k.lower(): v for k, v in raw.headers.items()}
        self.url = url

    def read(self, n: int) -> bytes:
        try:
            return bytes(self._raw.read(n))
        except Exception as exc:  # noqa: BLE001 - every read failure is transport
            if _is_tls(exc):
                raise TlsError(
                    f"TLS error while reading: {type(exc).__name__}"
                ) from None
            raise TransportError(f"read failed: {type(exc).__name__}") from None

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:  # noqa: BLE001
            pass


class UrllibTransport:
    """The real transport: stdlib urllib, default verified SSL, no redirects."""

    def __init__(self, config: HttpConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.ssl_context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ssl_context), _NoRedirect()
        )

    def open(self, method: str, url: str, headers: Mapping[str, str]) -> Response:
        try:
            req = urllib.request.Request(url, method=method, headers=dict(headers))
            raw = self._opener.open(req, timeout=self.config.timeout_s)
        except urllib.error.HTTPError as exc:  # a response, e.g. 404 or 302
            return _UrllibResponse(exc, url)
        except urllib.error.URLError as exc:
            if _is_tls(exc.reason):
                raise TlsError(f"TLS error: {type(exc.reason).__name__}") from None
            raise TransportError(f"connection error: {exc.reason!s:.200}") from None
        except (ssl.SSLError, ssl.CertificateError) as exc:
            raise TlsError(f"TLS error: {type(exc).__name__}") from None
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"connection error: {type(exc).__name__}") from None
        except Exception as exc:  # noqa: BLE001 - e.g. UnicodeEncodeError, ValueError
            raise TransportError(f"request failed: {type(exc).__name__}") from None
        try:
            return _UrllibResponse(raw, url)
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"bad response: {type(exc).__name__}") from None


# -- mock transport (tests) ------------------------------------------------


@dataclass
class MockResponse:
    """A canned response. ``fail_after``: raise TransportError after that many
    body bytes (a mid-stream drop)."""

    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    chunk: int | None = None
    fail_after: int | None = None


class _MockStream:
    def __init__(self, spec: MockResponse, url: str) -> None:
        self.status = spec.status
        self.headers = {k.lower(): v for k, v in spec.headers.items()}
        if "content-length" not in self.headers and spec.status == 200:
            self.headers["content-length"] = str(len(spec.body))
        self.url = url
        self._spec = spec
        self._pos = 0

    def read(self, n: int) -> bytes:
        spec = self._spec
        if spec.chunk:
            n = min(n, spec.chunk)
        if spec.fail_after is not None and self._pos >= spec.fail_after:
            raise TransportError("mock mid-stream drop")
        end = self._pos + n
        if spec.fail_after is not None:
            end = min(end, spec.fail_after)
        out = spec.body[self._pos : end]
        self._pos += len(out)
        return out

    def close(self) -> None:
        pass


class MockTransport:
    """In-memory transport. ``routes``: url -> MockResponse, an exception, or a
    list of those consumed one per call (the last one repeats)."""

    def __init__(self, routes: Mapping[str, Any]) -> None:
        self.routes: dict[str, Any] = dict(routes)
        self.calls: list[tuple[str, str]] = []
        self.headers_seen: list[Mapping[str, str]] = []
        self._pos: dict[str, int] = {}

    def open(self, method: str, url: str, headers: Mapping[str, str]) -> Response:
        self.calls.append((method, url))
        self.headers_seen.append(dict(headers))
        if url not in self.routes:
            return _MockStream(MockResponse(404), url)
        spec = self.routes[url]
        if isinstance(spec, list):
            i = self._pos.get(url, 0)
            self._pos[url] = i + 1
            spec = spec[min(i, len(spec) - 1)]
        if isinstance(spec, BaseException):
            raise spec
        if callable(spec):
            spec = spec()
        return _MockStream(spec, url)


# -- fetcher ------------------------------------------------------------------


@dataclass(frozen=True)
class DownloadResult:
    bytes_read: int
    final_url: str
    status: int = 200

    def to_dict(self) -> dict[str, Any]:
        return {
            "bytes_read": self.bytes_read,
            "final_url": self.final_url,
            "status": self.status,
        }


class Fetcher:
    """Paced, retrying, breaker-guarded fetcher over a :class:`Transport`."""

    def __init__(
        self,
        transport: Transport,
        config: HttpConfig = DEFAULT_CONFIG,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        *,
        catalog_hosts: Iterable[str] = (),
        on_event: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> None:
        import time

        self.transport = transport
        self.config = config
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self.catalog_hosts = frozenset(h.lower() for h in catalog_hosts)
        self._on_event = on_event
        self._last: dict[str, float] = {}
        self._fails: dict[str, int] = {}
        self._tripped_at: dict[str, float] = {}
        self.n_requests = 0
        #: Catalogue body bytes read per host (run stats).
        self.catalog_bytes: dict[str, int] = {}

    @property
    def tripped_hosts(self) -> set[str]:
        """Hosts whose breaker is open and still cooling down."""
        now = self._clock()
        cool = self.config.breaker_cooldown_s
        return {h for h, t in self._tripped_at.items() if now - t < cool}

    # -- helpers -------------------------------------------------------------
    def _event(self, kind: str, **data: Any) -> None:
        if self._on_event is not None:
            self._on_event(kind, data)

    def _pace(self, host: str) -> None:
        last = self._last.get(host)
        if last is not None:
            wait = last + self.config.min_interval_s - self._clock()
            if wait > 0:
                self._sleep(wait)
        self._last[host] = self._clock()

    def _fail(self, host: str) -> None:
        n = self._fails.get(host, 0) + 1
        self._fails[host] = n
        if n >= self.config.breaker_consecutive_failures:
            if host not in self._tripped_at:
                self._event("host_tripped", host=host, failures=n)
            self._tripped_at[host] = self._clock()

    def _gate(self, host: str, waits_left: int) -> int:
        """Block on a tripped host: sleep out the cooldown if waits are left,
        else raise. Once cooled down, let one probe through (half-open)."""
        while host in self._tripped_at:
            left = (
                self._tripped_at[host] + self.config.breaker_cooldown_s - self._clock()
            )
            if left <= 0:
                del self._tripped_at[host]
                # half-open: a single failure re-trips
                self._fails[host] = self.config.breaker_consecutive_failures - 1
                self._event("host_probe", host=host)
                break
            if waits_left <= 0:
                raise HostTripped(f"host {host} is tripped")
            waits_left -= 1
            self._event("host_wait", host=host, delay_s=left)
            self._sleep(left)
        return waits_left

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        cfg = self.config
        if retry_after is not None:
            try:
                return min(max(float(retry_after.strip()), 0.0), cfg.max_retry_after_s)
            except ValueError:
                pass  # an HTTP-date: fall back to our own backoff
        return min(cfg.backoff_base_s * (2**attempt), cfg.backoff_max_s)

    def _open_once(self, url: str, *, wait: bool = False) -> Response:
        """Open ``url`` with retries; returns any non-retryable response."""
        host = host_of(url)
        headers = {"User-Agent": self.config.user_agent, "Accept": "*/*"}
        attempt = 0
        waits = self.config.catalog_trip_waits if wait else 0
        while True:
            waits = self._gate(host, waits)
            self._pace(host)
            self.n_requests += 1
            retry_after: str | None = None
            try:
                resp = self.transport.open("GET", url, headers)
            except TlsError:
                self._fail(host)
                raise
            except TransportError as exc:
                self._fail(host)
                err: FetchError = exc
            else:
                if resp.status not in _RETRY_STATUS:
                    if resp.status < 500:
                        self._fails[host] = 0
                    return resp
                retry_after = resp.headers.get("retry-after")
                resp.close()
                self._fail(host)
                err = HttpStatusError(resp.status, url)
            if host in self._tripped_at:
                if waits > 0:
                    continue  # _gate sleeps out the cooldown, then probes
                raise HostTripped(f"host {host} tripped ({err.reason})")
            if attempt >= self.config.max_retries:
                raise err
            delay = self._backoff(attempt, retry_after)
            self._event(
                "retry",
                host=host,
                attempt=attempt + 1,
                reason=err.reason,
                delay_s=delay,
            )
            self._sleep(delay)
            attempt += 1

    def _follow(self, url: str, *, catalog: bool) -> Response:
        """Open with redirects followed under the catalogue or payload policy."""
        current = _ascii_url(url)
        for _ in range(self.config.max_redirects + 1):
            self._check_url(current, catalog=catalog)
            resp = self._open_once(current, wait=catalog)
            if resp.status not in _REDIRECTS:
                return resp
            loc = resp.headers.get("location")
            resp.close()
            if not loc:
                raise HttpStatusError(resp.status, current)
            try:
                current = urllib.parse.urljoin(current, _ascii_url(loc))
            except ValueError:
                raise RedirectRefused("malformed redirect Location") from None
        raise RedirectRefused(f"more than {self.config.max_redirects} redirects")

    def _check_url(self, url: str, *, catalog: bool) -> None:
        try:
            parts = urllib.parse.urlsplit(url)
            parts.port  # noqa: B018 - raises on a bad port
        except ValueError:
            raise RedirectRefused("malformed URL") from None
        if parts.scheme != "https":
            raise RedirectRefused(f"refused non-https URL (scheme {parts.scheme!r})")
        host = (parts.hostname or "").lower()
        if catalog and host not in self.catalog_hosts:
            raise RedirectRefused(f"catalogue host {host!r} is not allowlisted")

    # -- public ------------------------------------------------------------
    def get(self, url: str, max_bytes: int) -> bytes:
        """The planners' Getter: the whole body of ``url`` (allowlisted hosts)."""
        resp = self._follow(url, catalog=True)
        try:
            if resp.status != 200:
                raise HttpStatusError(resp.status, url)
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise TooLarge(f"{url}: declared {declared} > {max_bytes} bytes")
            buf = bytearray()
            start = self._clock()
            while True:
                chunk = resp.read(min(self.config.chunk_bytes, max_bytes + 1))
                if not chunk:
                    break
                buf += chunk
                if len(buf) > max_bytes:
                    raise TooLarge(f"{url}: body over {max_bytes} bytes")
                if self._clock() - start > self.config.get_deadline_s:
                    raise TransportError(f"{url}: body read past the get deadline")
            host = host_of(resp.url or url)
            self.catalog_bytes[host] = self.catalog_bytes.get(host, 0) + len(buf)
            return bytes(buf)
        finally:
            resp.close()

    def download(
        self,
        url: str,
        dest_path: Path,
        max_bytes: int,
        hashers: Sequence[Any],
    ) -> DownloadResult:
        """Stream ``url`` into ``dest_path``, updating every hasher per chunk.

        Aborts with :class:`TooLarge` past ``max_bytes``. Every raised FetchError
        carries ``bytes_read``.
        """
        resp = self._follow(url, catalog=False)
        n = 0
        try:
            if resp.status != 200:
                raise HttpStatusError(resp.status, url)
            final_url = resp.url
            declared = resp.headers.get("content-length")
            if declared and declared.strip().isdigit() and int(declared) > max_bytes:
                raise TooLarge(f"declared {declared} > {max_bytes} bytes")
            start = self._clock()
            with open(dest_path, "wb") as out:
                while True:
                    try:
                        chunk = resp.read(self.config.chunk_bytes)
                    except FetchError as exc:
                        exc.bytes_read = n
                        self._fail(host_of(final_url))
                        raise
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > max_bytes:
                        raise TooLarge(f"body over {max_bytes} bytes", bytes_read=n)
                    for h in hashers:
                        h.update(chunk)
                    out.write(chunk)
                    if self._clock() - start > self.config.download_deadline_s:
                        raise TransportError(
                            "body read past the download deadline", bytes_read=n
                        )
            return DownloadResult(bytes_read=n, final_url=final_url)
        finally:
            resp.close()
