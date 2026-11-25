"""The HTTP layer: pacing, retries, breaker, redirects, TLS, streaming bounds."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from sherlock.collect.http import (
    Fetcher,
    FetchError,
    HostTripped,
    HttpConfig,
    HttpStatusError,
    MockResponse,
    MockTransport,
    RedirectRefused,
    TlsError,
    TooLarge,
    TransportError,
    UrllibTransport,
)


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


def _fetcher(transport, *, hosts=("api.example.test",), **cfg):
    c = FakeClock()
    f = Fetcher(
        transport,
        HttpConfig(**cfg),
        clock=c.clock,
        sleep=c.sleep,
        catalog_hosts=hosts,
    )
    return f, c


def test_get_returns_body_and_paces_per_host():
    t = MockTransport(
        {
            "https://api.example.test/a": MockResponse(200, b"A"),
            "https://api.example.test/b": MockResponse(200, b"B"),
        }
    )
    f, c = _fetcher(t)
    assert f.get("https://api.example.test/a", 10) == b"A"
    assert f.get("https://api.example.test/b", 10) == b"B"
    assert c.sleeps == [pytest.approx(1.0)]


def test_get_oversize_raises():
    t = MockTransport({"https://api.example.test/a": MockResponse(200, b"x" * 20)})
    f, _ = _fetcher(t)
    with pytest.raises(TooLarge):
        f.get("https://api.example.test/a", 10)


def test_retry_after_honoured_with_injected_sleep():
    url = "https://api.example.test/a"
    t = MockTransport(
        {
            url: [
                MockResponse(429, b"", {"Retry-After": "7"}),
                MockResponse(503, b""),
                MockResponse(200, b"ok"),
            ]
        }
    )
    f, c = _fetcher(t)
    assert f.get(url, 10) == b"ok"
    assert len(t.calls) == 3
    assert 7.0 in [round(s, 3) for s in c.sleeps]


def test_retry_after_is_capped():
    url = "https://api.example.test/a"
    t = MockTransport(
        {
            url: [
                MockResponse(429, b"", {"Retry-After": "99999"}),
                MockResponse(200, b"k"),
            ]
        }
    )
    f, c = _fetcher(t)
    f.get(url, 10)
    assert max(c.sleeps) <= 900.0


def test_404_not_retried():
    url = "https://api.example.test/a"
    t = MockTransport({url: MockResponse(404, b"")})
    f, _ = _fetcher(t)
    with pytest.raises(HttpStatusError) as ei:
        f.get(url, 10)
    assert ei.value.status == 404
    assert len(t.calls) == 1


def test_retries_exhausted_raises():
    url = "https://api.example.test/a"
    t = MockTransport({url: MockResponse(500, b"")})
    f, _ = _fetcher(t, max_retries=2)
    with pytest.raises(HttpStatusError):
        f.get(url, 10)
    assert len(t.calls) == 3


def test_connection_error_retried():
    url = "https://api.example.test/a"
    t = MockTransport({url: [TransportError("reset"), MockResponse(200, b"ok")]})
    f, _ = _fetcher(t)
    assert f.get(url, 10) == b"ok"


def test_breaker_trips_inside_retry_loop():
    url = "https://api.example.test/a"
    t = MockTransport({url: MockResponse(503, b"")})
    f, _ = _fetcher(
        t, max_retries=50, breaker_consecutive_failures=4, catalog_trip_waits=0
    )
    with pytest.raises(HostTripped):
        f.get(url, 10)
    assert len(t.calls) == 4
    with pytest.raises(HostTripped):
        f.get(url, 10)
    assert len(t.calls) == 4  # no further network once tripped
    assert "api.example.test" in f.tripped_hosts


def test_breaker_resets_on_success():
    url = "https://api.example.test/a"
    seq = [MockResponse(503, b""), MockResponse(200, b"k")] * 5
    t = MockTransport({url: seq})
    f, _ = _fetcher(t, breaker_consecutive_failures=2)
    for _ in range(5):
        assert f.get(url, 10) == b"k"


def test_tls_failure_never_bypassed():
    url = "https://api.example.test/a"
    t = MockTransport({url: TlsError("certificate verify failed")})
    f, _ = _fetcher(t)
    with pytest.raises(TlsError):
        f.get(url, 10)
    assert len(t.calls) == 1  # never retried, never with verification off
    ctx = UrllibTransport(HttpConfig()).ssl_context
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_catalogue_cross_host_redirect_refused():
    url = "https://api.example.test/a"
    t = MockTransport(
        {
            url: MockResponse(302, b"", {"Location": "https://evil.example.test/a"}),
            "https://evil.example.test/a": MockResponse(200, b"x"),
        }
    )
    f, _ = _fetcher(t)
    with pytest.raises(RedirectRefused):
        f.get(url, 10)
    assert [u for _, u in t.calls] == [url]


def test_catalogue_off_allowlist_initial_url_refused():
    t = MockTransport({})
    f, _ = _fetcher(t)
    with pytest.raises(RedirectRefused):
        f.get("https://other.example.test/x", 10)
    with pytest.raises(FetchError):
        f.get("http://api.example.test/x", 10)
    assert t.calls == []


def test_catalogue_same_host_relative_redirect_followed():
    t = MockTransport(
        {
            "https://api.example.test/a": MockResponse(301, b"", {"Location": "/b"}),
            "https://api.example.test/b": MockResponse(200, b"B"),
        }
    )
    f, _ = _fetcher(t)
    assert f.get("https://api.example.test/a", 10) == b"B"


def test_download_streams_hashes_and_follows_cross_host_https(tmp_path):
    body = b"payload" * 1000
    t = MockTransport(
        {
            "https://api.example.test/p": MockResponse(
                302, b"", {"Location": "https://cdn.example.test/p"}
            ),
            "https://cdn.example.test/p": MockResponse(200, body, chunk=100),
        }
    )
    f, _ = _fetcher(t)
    h = hashlib.sha256()
    dest = tmp_path / "x.part"
    res = f.download("https://api.example.test/p", dest, 10**6, [h])
    assert res.bytes_read == len(body)
    assert res.final_url == "https://cdn.example.test/p"
    assert h.hexdigest() == hashlib.sha256(body).hexdigest()
    assert dest.read_bytes() == body


def test_payload_https_to_http_redirect_refused(tmp_path):
    t = MockTransport(
        {
            "https://api.example.test/p": MockResponse(
                302, b"", {"Location": "http://cdn.example.test/p"}
            ),
        }
    )
    f, _ = _fetcher(t)
    with pytest.raises(RedirectRefused) as ei:
        f.download("https://api.example.test/p", tmp_path / "x.part", 100, [])
    assert ei.value.bytes_read == 0


def test_download_aborts_past_max_bytes(tmp_path):
    t = MockTransport(
        {
            "https://api.example.test/p": MockResponse(
                200, b"x" * 1000, {"content-length": ""}, chunk=64
            )
        }
    )
    f, _ = _fetcher(t)
    with pytest.raises(TooLarge) as ei:
        f.download("https://api.example.test/p", tmp_path / "x.part", 100, [])
    assert 0 < ei.value.bytes_read <= 100 + 64


def test_download_mid_stream_failure_carries_bytes_and_is_not_retried(tmp_path):
    t = MockTransport(
        {
            "https://api.example.test/p": MockResponse(
                200, b"x" * 300, chunk=100, fail_after=200
            )
        }
    )
    f, _ = _fetcher(t)
    with pytest.raises(TransportError) as ei:
        f.download("https://api.example.test/p", tmp_path / "x.part", 10**6, [])
    assert ei.value.bytes_read == 200
    assert len(t.calls) == 1


def test_user_agent_is_generic():
    import re

    ua = HttpConfig().user_agent
    assert re.fullmatch(r"[a-z0-9./ ()-]+", ua)  # no names, no contact details


def test_user_agent_sent_on_get_and_download(tmp_path):
    t = MockTransport(
        {
            "https://api.example.test/a": MockResponse(200, b"A"),
            "https://api.example.test/p": MockResponse(200, b"P"),
        }
    )
    f, _ = _fetcher(t)
    f.get("https://api.example.test/a", 10)
    f.download("https://api.example.test/p", tmp_path / "x.part", 10, [])
    assert len(t.headers_seen) == 2
    for h in t.headers_seen:
        assert h["User-Agent"] == HttpConfig().user_agent


def test_breaker_half_open_after_cooldown(tmp_path):
    url = "https://api.example.test/a"
    t = MockTransport(
        {url: [MockResponse(503, b""), MockResponse(503, b""), MockResponse(200, b"k")]}
    )
    f, c = _fetcher(
        t, max_retries=0, breaker_consecutive_failures=2, breaker_cooldown_s=100
    )
    for _ in range(2):
        with pytest.raises((HttpStatusError, HostTripped)):
            f.download("https://api.example.test/a", tmp_path / "x.part", 10, [])
    assert "api.example.test" in f.tripped_hosts
    with pytest.raises(HostTripped):
        f.download(url, tmp_path / "x.part", 10, [])
    assert len(t.calls) == 2
    c.t += 101  # cooldown over: one probe allowed, success closes the breaker
    f.download(url, tmp_path / "x.part", 10, [])
    assert "api.example.test" not in f.tripped_hosts


def test_half_open_probe_failure_retrips(tmp_path):
    url = "https://api.example.test/a"
    t = MockTransport({url: MockResponse(503, b"")})
    f, c = _fetcher(
        t, max_retries=0, breaker_consecutive_failures=3, breaker_cooldown_s=100
    )
    for _ in range(3):
        with pytest.raises((HttpStatusError, HostTripped)):
            f.download(url, tmp_path / "x.part", 10, [])
    c.t += 101
    with pytest.raises((HttpStatusError, HostTripped)):
        f.download(url, tmp_path / "x.part", 10, [])
    assert len(t.calls) == 4  # one probe, then tripped again
    assert "api.example.test" in f.tripped_hosts


def test_catalogue_get_waits_out_a_short_outage():
    url = "https://api.example.test/a"
    t = MockTransport({url: [MockResponse(503, b"")] * 2 + [MockResponse(200, b"ok")]})
    f, c = _fetcher(
        t, max_retries=0, breaker_consecutive_failures=2, breaker_cooldown_s=100
    )
    with pytest.raises((HttpStatusError, HostTripped)):
        f.get(url, 10)
    # the next catalogue get sleeps through the cooldown, probes and succeeds
    assert f.get(url, 10) == b"ok"
    assert any(s >= 99 for s in c.sleeps)


def test_non_ascii_and_malformed_location_handled(tmp_path):
    t = MockTransport(
        {
            "https://api.example.test/a": MockResponse(
                302, b"", {"Location": "https://cdn.example.test/\u00fcber/x"}
            ),
            "https://cdn.example.test/%C3%BCber/x": MockResponse(200, b"P"),
            "https://api.example.test/b": MockResponse(
                302, b"", {"Location": "https://[::1/x"}
            ),
        }
    )
    f, _ = _fetcher(t)
    res = f.download("https://api.example.test/a", tmp_path / "a.part", 10, [])
    assert res.final_url == "https://cdn.example.test/%C3%BCber/x"
    with pytest.raises(FetchError) as ei:
        f.download("https://api.example.test/b", tmp_path / "b.part", 10, [])
    assert ei.value.bytes_read == 0


def test_urllib_transport_converts_odd_exceptions():
    t = UrllibTransport(HttpConfig(timeout_s=1))
    with pytest.raises(TransportError):
        t.open("GET", "https://exa\u00e9mple.invalid:99999999/x", {})
    with pytest.raises(TransportError):
        t.open("GET", "https://[::1/x", {})


def test_download_declared_oversize_refused_before_reading(tmp_path):
    t = MockTransport({"https://api.example.test/p": MockResponse(200, b"x" * 1000)})
    f, _ = _fetcher(t)
    with pytest.raises(TooLarge) as ei:
        f.download("https://api.example.test/p", tmp_path / "x.part", 100, [])
    assert ei.value.bytes_read == 0


def test_download_wall_clock_deadline(tmp_path):
    t = MockTransport(
        {"https://api.example.test/p": MockResponse(200, b"x" * 1000, chunk=10)}
    )
    c = FakeClock()

    class SlowClock:
        def __call__(self):
            c.t += 1.0  # each clock read is a second later
            return c.t

    f = Fetcher(
        t,
        HttpConfig(download_deadline_s=20, min_interval_s=0),
        clock=SlowClock(),
        sleep=c.sleep,
        catalog_hosts=("api.example.test",),
    )
    with pytest.raises(TransportError) as ei:
        f.download("https://api.example.test/p", tmp_path / "x.part", 10**6, [])
    assert 0 < ei.value.bytes_read < 1000
    with pytest.raises(TransportError):
        Fetcher(
            t,
            HttpConfig(get_deadline_s=20, min_interval_s=0),
            clock=SlowClock(),
            sleep=c.sleep,
            catalog_hosts=("api.example.test",),
        ).get("https://api.example.test/p", 10**6)


def test_catalogue_bytes_counted_per_host():
    t = MockTransport({"https://api.example.test/a": MockResponse(200, b"abc")})
    f, _ = _fetcher(t)
    f.get("https://api.example.test/a", 10)
    assert f.catalog_bytes == {"api.example.test": 3}
