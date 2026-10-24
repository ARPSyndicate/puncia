"""Unit tests for puncia. Everything here is offline — no API calls."""

import asyncio
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from multidict import CIMultiDict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from puncia import (  # noqa: E402
    PunciaError,
    RateLimiter,
    build_request,
    read_key,
    safe_output_path,
    sbom_process,
    store_key,
)
from puncia.__main__ import (  # noqa: E402
    emit_result,
    plan_bulk,
    query_api,
)
import puncia.__main__ as puncia_main  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_key_store(tmp_path, monkeypatch):
    """Never let a developer's real ~/.puncia or $PUNCIA_API_KEY leak into a
    test: a CLI test that omits --api-key would otherwise silently switch to
    the authenticated code paths on one machine and not another."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("PUNCIA_API_KEY", raising=False)


# --------------------------------------------------------------------------- #
# Output integrity — piped stdout must always be machine-readable
# --------------------------------------------------------------------------- #

def test_long_values_survive_piping_unwrapped(capsys):
    """Rich wraps at the console width; piped output must not be line-wrapped."""
    data = ["x" * 500, "sub." * 40 + "example.com"]
    emit_result(data)
    captured = capsys.readouterr().out
    assert json.loads(captured) == data, "piped output was corrupted by wrapping"


def test_nested_result_survives_piping(capsys):
    data = {"description": "y" * 400, "aliases": ["CVE-2021-3450"] * 20}
    emit_result(data)
    assert json.loads(capsys.readouterr().out) == data


# --------------------------------------------------------------------------- #
# Path containment — regression tests for the SBOM path-traversal report
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "hostile",
    [
        "../../ESCAPED",
        "../../../escaped/deep/PWNED",
        "..",
        "../",
        "/etc/passwd",
        "/absolute/path",
        "a/../../b",
        "..\\..\\windows",
        "C:\\Windows\\system32",
        "nul\x00byte",
        "trailing/",
    ],
)
def test_hostile_component_names_stay_inside_root(tmp_path, hostile):
    """No SBOM component name may place a file outside the output directory."""
    root = tmp_path.resolve()
    destination = safe_output_path(root, "exploit", hostile)
    if destination is None:
        return  # rejected outright, which is also a safe outcome
    assert root in destination.parents, f"{hostile!r} escaped to {destination}"
    # The mode directory is the only level we ever create beneath the root.
    assert destination.parent == root / "exploit"


def test_traversal_does_not_create_directories_outside_root(tmp_path):
    """The containment check must happen before any mkdir."""
    root = (tmp_path / "out").resolve()
    root.mkdir()
    jobs, _ = plan_bulk({"exploit": ["../../ESCAPED@1.0"]}, root)
    for _, _, destination in jobs:
        destination.parent.mkdir(parents=True, exist_ok=True)
    assert not (tmp_path / "ESCAPED@1.0.json").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / "out"]


def test_ordinary_names_are_preserved(tmp_path):
    root = tmp_path.resolve()
    destination = safe_output_path(root, "exploit", "log4j-core@2.14.1")
    assert destination == root / "exploit" / "log4j-core@2.14.1.json"


def test_scoped_package_names_are_flattened_not_nested(tmp_path):
    """npm/Go names contain slashes; they must not become nested directories."""
    root = tmp_path.resolve()
    destination = safe_output_path(root, "exploit", "@scope/pkg@1.0.0")
    assert destination is not None
    assert destination.parent == root / "exploit"
    assert "/" not in destination.name.replace(".json", "")


def test_empty_and_dot_only_names_are_rejected(tmp_path):
    root = tmp_path.resolve()
    for name in ("", "   ", ".", "..", "...", " . "):
        assert safe_output_path(root, "exploit", name) is None


def test_separator_only_names_collapse_to_a_contained_file(tmp_path):
    """Separators sanitise to a placeholder rather than being dropped."""
    root = tmp_path.resolve()
    for name in ("/", "///", "\\"):
        destination = safe_output_path(root, "exploit", name)
        assert destination is not None
        assert destination.parent == root / "exploit"


def test_overlong_names_are_truncated_and_unique(tmp_path):
    root = tmp_path.resolve()
    first = safe_output_path(root, "exploit", "a" * 400 + "one")
    second = safe_output_path(root, "exploit", "a" * 400 + "two")
    assert first is not None and second is not None
    assert first != second, "truncation must not collide distinct components"
    assert len(first.name) < 255


# --------------------------------------------------------------------------- #
# Request building
# --------------------------------------------------------------------------- #

def test_subdomain_url():
    assert build_request("subdomain", "example.com") == (
        "https://api.subdomain.center/?domain=example.com"
    )


def test_replica_uses_octopus_engine():
    url = build_request("replica", "example.com")
    assert "engine=octopus" in url and "domain=example.com" in url


def test_keyword_uses_ammonites_engine():
    url = build_request("keyword", "vpn")
    assert "engine=ammonites" in url and "keyword=vpn" in url


def test_keyword_can_be_scoped_to_a_domain():
    """ammonites accepts keyword and domain together to narrow the search."""
    url = build_request("keyword", "blog", scope="bandcamp.com")
    assert "engine=ammonites" in url
    assert "keyword=blog" in url
    assert "domain=bandcamp.com" in url


def test_keyword_scope_combines_with_match():
    url = build_request("keyword", "blog", match="prefix", scope="bandcamp.com")
    assert "keyword=blog" in url and "domain=bandcamp.com" in url and "match=prefix" in url


def test_scope_is_url_encoded():
    url = build_request("keyword", "vpn", scope="a b&c=d")
    assert "a+b%26c%3Dd" in url or "a%20b%26c%3Dd" in url


def test_scope_rejected_for_modes_that_do_not_support_it():
    for mode in ("subdomain", "replica", "exploit"):
        with pytest.raises(PunciaError, match="does not support --domain"):
            build_request(mode, "example.com", scope="other.com")


def test_enrich_mode_is_gone():
    with pytest.raises(PunciaError, match="unknown mode 'enrich'"):
        build_request("enrich", "CVE-2021-44228")
    assert "enrich" not in puncia_main.ALL_MODES


def test_old_bulk_files_with_enrich_degrade_to_a_warning(tmp_path):
    jobs, warnings = plan_bulk(
        {"exploit": ["CVE-2021-44228"], "enrich": ["CVE-2021-44228"]}, tmp_path.resolve()
    )
    assert [job[0] for job in jobs] == ["exploit"]
    assert any("unknown mode 'enrich'" in warning for warning in warnings)


def test_special_characters_are_url_encoded():
    """A query containing & or # must not inject extra query parameters."""
    url = build_request("exploit", "foo&admin=1 bar#frag")
    assert "&admin=1" not in url.split("keyword=")[1].split("&")[0]
    assert "%26" in url and "%23" in url and " " not in url


def test_inline_pipe_match_is_parsed():
    url = build_request("keyword", "blog|prefix")
    assert "keyword=blog" in url and "match=prefix" in url
    assert "prefixblog" not in url  # regression: match must not be concatenated onto the query


def test_explicit_match_flag():
    url = build_request("exploit", "grafana", match="exact")
    assert "keyword=grafana" in url and "match=exact" in url


def test_watchlist_shortcuts():
    assert build_request("exploit", "^WATCHLIST_IDES").endswith("/watchlist/identifiers")
    assert build_request("exploit", "^WATCHLIST_INFO").endswith("/watchlist/describers")
    assert build_request("exploit", "^WATCHLIST_TECH").endswith("/watchlist/technologies")


def test_noncve_is_path_based():
    assert build_request("noncve", "exploitable").endswith("/noncve/exploitable")


def test_unknown_mode_is_rejected():
    with pytest.raises(PunciaError, match="unknown mode"):
        build_request("bogus", "x")


def test_empty_query_is_rejected():
    with pytest.raises(PunciaError, match="non-empty query"):
        build_request("subdomain", "   ")


def test_invalid_match_is_rejected():
    with pytest.raises(PunciaError, match="invalid match"):
        build_request("keyword", "blog", match="substring")


def test_invalid_noncve_engine_is_rejected():
    with pytest.raises(PunciaError, match="invalid value"):
        build_request("noncve", "atlantis")


def test_match_unsupported_for_subdomain():
    with pytest.raises(PunciaError, match="does not support"):
        build_request("subdomain", "example.com", match="exact")


# --------------------------------------------------------------------------- #
# Pagination — limit/offset URL building
# --------------------------------------------------------------------------- #

def test_limit_and_offset_are_added_to_subdomain_center_urls():
    url = build_request("subdomain", "example.com", limit=50000, offset=100000)
    assert "limit=50000" in url and "offset=100000" in url


def test_limit_offset_rejected_for_exploit_observer_modes():
    for mode in ("exploit", "noncve"):
        query = "exploitable" if mode == "noncve" else "CVE-2021-3450"
        with pytest.raises(PunciaError, match="does not support pagination"):
            build_request(mode, query, limit=100)
        with pytest.raises(PunciaError, match="does not support pagination"):
            build_request(mode, query, offset=0)


def test_negative_limit_and_offset_rejected():
    with pytest.raises(PunciaError, match="--limit must be >= 1"):
        build_request("subdomain", "example.com", limit=-1)
    with pytest.raises(PunciaError, match="--offset must be >= 0"):
        build_request("subdomain", "example.com", offset=-1)


def test_zero_limit_is_rejected_everywhere():
    """limit=0 would make a walk judge every page full and never end on its own."""
    with pytest.raises(PunciaError, match="--limit must be >= 1"):
        build_request("subdomain", "example.com", limit=0)
    with pytest.raises(PunciaError, match="between 1 and 1000"):
        build_request("nuclei", "candidates", limit=0)


def test_subdomain_center_limit_above_absolute_bound_is_rejected():
    build_request("subdomain", "example.com", limit=puncia_main.SUBDOMAIN_MAX_PAGE)
    with pytest.raises(PunciaError, match="must be <= 1000000"):
        build_request("subdomain", "example.com", limit=puncia_main.SUBDOMAIN_MAX_PAGE + 1)


def test_scope_rejected_for_path_based_modes_too():
    """Regression: the --domain check used to sit after the /noncve branch
    returned, so `puncia noncve exploitable --domain x` dropped it silently."""
    with pytest.raises(PunciaError, match="does not support --domain"):
        build_request("noncve", "exploitable", scope="example.com")
    with pytest.raises(PunciaError, match="does not support --domain"):
        build_request("nuclei", "candidates", scope="example.com")


def test_inline_match_tolerates_whitespace():
    url = build_request("keyword", "blog | prefix")
    assert "keyword=blog" in url and "match=prefix" in url


def test_static_pseudo_query_tolerates_surrounding_whitespace():
    assert build_request("exploit", "  ^STATS ") == "https://api.exploit.observer/stats"


def test_offset_zero_is_sent_explicitly_not_omitted():
    """offset=0 is a legitimate explicit value, distinct from "no offset"."""
    url = build_request("subdomain", "example.com", offset=0)
    assert "offset=0" in url


# --------------------------------------------------------------------------- #
# Static endpoints — health/stats/watchlists (unauthenticated, unlimited)
# --------------------------------------------------------------------------- #

def test_subdomain_health_dispatches_to_the_right_url():
    assert build_request("subdomain", "^HEALTH") == "https://api.subdomain.center/health"


def test_exploit_health_and_stats_dispatch_to_the_right_urls():
    assert build_request("exploit", "^HEALTH") == "https://api.exploit.observer/health"
    assert build_request("exploit", "^STATS") == "https://api.exploit.observer/stats"


def test_watchlist_shortcuts_still_work_alongside_new_static_endpoints():
    assert build_request("exploit", "^WATCHLIST_IDES").endswith("/watchlist/identifiers")
    assert build_request("exploit", "^WATCHLIST_INFO").endswith("/watchlist/describers")
    assert build_request("exploit", "^WATCHLIST_TECH").endswith("/watchlist/technologies")


def test_static_pseudo_query_is_mode_specific():
    """The same spelling means a different URL depending on which mode it's under."""
    assert build_request("subdomain", "^HEALTH") != build_request("exploit", "^HEALTH")


def test_health_pseudo_query_not_recognized_under_replica_or_keyword():
    """^HEALTH only dispatches under `subdomain`; replica/keyword treat it as a literal query."""
    assert not puncia_main._is_static_query("replica", "^HEALTH")
    assert not puncia_main._is_static_query("keyword", "^HEALTH")


def test_query_api_skips_rate_limit_for_static_endpoints_without_a_key(monkeypatch):
    """Static pseudo-queries are never rate-limited by puncia."""
    seen_limiter = {}

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        seen_limiter["value"] = limiter
        return {"status": "ok"}, {}

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    result = asyncio.run(query_api("exploit", "^HEALTH", apikey=""))
    assert result == {"status": "ok"}
    assert seen_limiter["value"] is None


def test_query_api_does_not_auto_paginate_static_endpoints(monkeypatch):
    """A dict/health response must never be routed through the page-walker."""
    called = {}

    async def fake_fetch_all_pages(*a, **k):
        called["auto_used"] = True
        return {}

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        called["single_page_used"] = True
        return {"status": "ok"}, {}

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)

    result = asyncio.run(query_api("subdomain", "^HEALTH", apikey="ARPS-x"))
    assert result == {"status": "ok"}
    assert called.get("single_page_used") is True
    assert "auto_used" not in called


def test_keyword_over_2048_chars_rejected_before_it_becomes_a_silent_empty_result():
    with pytest.raises(PunciaError, match="over Exploit Observer's 2048-char limit"):
        build_request("exploit", "a" * 2049)


def test_keyword_at_2048_chars_is_accepted():
    url = build_request("exploit", "a" * 2048)
    assert "keyword=" + "a" * 2048 in url


# --------------------------------------------------------------------------- #
# Live crawl — subdomain (cuttlefish) only, requires an API key
# --------------------------------------------------------------------------- #

def test_crawl_true_is_added_for_subdomain_mode():
    url = build_request("subdomain", "example.com", crawl=True)
    assert "crawl=true" in url


def test_crawl_omitted_when_false():
    url = build_request("subdomain", "example.com", crawl=False)
    assert "crawl" not in url


def test_crawl_rejected_for_non_cuttlefish_modes():
    for mode, query in (("replica", "example.com"), ("keyword", "vpn"), ("exploit", "CVE-2021-3450")):
        with pytest.raises(PunciaError, match="does not support --crawl"):
            build_request(mode, query, crawl=True)


def test_query_api_requires_a_key_for_crawl(monkeypatch):
    async def fake_fetch(*a, **k):
        raise AssertionError("must not reach the network without a key")

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    with pytest.raises(PunciaError, match="--crawl requires an API key"):
        asyncio.run(query_api("subdomain", "example.com", apikey="", crawl=True))


def test_crawl_is_only_sent_on_the_first_page_of_an_auto_paginated_walk(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com"], {"X-Truncated": "true", "X-Next-Offset": "1"}),
            (["b.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", 2, {}, None, 0, 30.0,
            crawl=True,
        )
    )
    assert result == ["a.com", "b.com"]
    assert "crawl=true" in fake.urls[0]
    assert "crawl" not in fake.urls[1]


def test_on_crawl_callback_receives_first_page_headers_only(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com"], {"X-Truncated": "true", "X-Next-Offset": "1", "X-Crawl-Status": "fresh"}),
            (["b.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)
    seen = []

    asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", 2, {}, None, 0, 30.0,
            crawl=True, on_crawl=lambda h: seen.append(h),
        )
    )
    assert len(seen) == 1
    assert seen[0]["X-Crawl-Status"] == "fresh"


# --------------------------------------------------------------------------- #
# Transport — error surfacing and Retry-After handling
# --------------------------------------------------------------------------- #

def test_extract_error_message_from_json_body():
    assert puncia_main._extract_error_message('{"error": "missing domain"}') == "missing domain"


def test_extract_error_message_returns_none_for_non_error_json():
    assert puncia_main._extract_error_message('{"other": "field"}') is None
    assert puncia_main._extract_error_message("[1, 2, 3]") is None


def test_extract_error_message_returns_none_for_non_json():
    assert puncia_main._extract_error_message("not json at all") is None


def test_parse_retry_after_uses_header_when_valid():
    assert puncia_main._parse_retry_after("7", fallback=2.0) == 7.0
    assert puncia_main._parse_retry_after("0", fallback=2.0) == 0.0


def test_parse_retry_after_falls_back_on_missing_or_invalid():
    assert puncia_main._parse_retry_after(None, fallback=2.0) == 2.0
    assert puncia_main._parse_retry_after("not-a-number", fallback=2.0) == 2.0
    assert puncia_main._parse_retry_after("-5", fallback=2.0) == 2.0


class _FakeResponse:
    def __init__(self, status, json_data=None, text_data="", headers=None):
        self.status = status
        self._json_data = json_data
        self._text_data = text_data
        self.headers = headers or {}

    async def json(self, content_type=None):
        return self._json_data

    async def text(self):
        return self._text_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class _FakeGetSession:
    """Replays a queue of canned responses for consecutive `.get()` calls."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.urls: list = []
        self.timeouts: list = []

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        self.timeouts.append(timeout)
        if not self.responses:
            raise AssertionError("more requests made than responses were queued")
        return self.responses.pop(0)


def test_fetch_applies_the_timeout_per_request():
    """`timeout=` must hold for a caller-supplied session too, not only for
    the short-lived session query_api builds itself."""
    import aiohttp

    session = _FakeGetSession([_FakeResponse(200, json_data=[])])
    asyncio.run(
        puncia_main._fetch(session, "https://api.subdomain.center/?domain=x", {}, None, retries=0, timeout=7.5)
    )
    assert isinstance(session.timeouts[0], aiohttp.ClientTimeout)
    assert session.timeouts[0].total == 7.5


def test_fetch_honors_retry_after_header_on_429(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(puncia_main.asyncio, "sleep", fake_sleep)
    session = _FakeGetSession(
        [
            _FakeResponse(429, text_data='{"error": "slow down"}', headers={"Retry-After": "7"}),
            _FakeResponse(200, json_data=["a.com"]),
        ]
    )

    data, headers = asyncio.run(
        puncia_main._fetch(session, "https://api.subdomain.center/?domain=x", {}, None, retries=1, timeout=30.0)
    )
    assert data == ["a.com"]
    assert sleeps == [7.0]


def test_fetch_surfaces_json_error_message_on_exhausted_retries(monkeypatch):
    async def fake_sleep(seconds):
        pass

    monkeypatch.setattr(puncia_main.asyncio, "sleep", fake_sleep)
    session = _FakeGetSession(
        [_FakeResponse(400, text_data='{"error": "missing required parameter: domain"}')]
    )

    with pytest.raises(PunciaError, match="missing required parameter: domain"):
        asyncio.run(
            puncia_main._fetch(session, "https://api.subdomain.center/", {}, None, retries=0, timeout=30.0)
        )


def test_fetch_falls_back_to_default_backoff_when_no_retry_after(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(puncia_main.asyncio, "sleep", fake_sleep)
    session = _FakeGetSession(
        [
            _FakeResponse(429, text_data="", headers={}),
            _FakeResponse(200, json_data=["a.com"]),
        ]
    )

    asyncio.run(
        puncia_main._fetch(session, "https://api.subdomain.center/?domain=x", {}, None, retries=1, timeout=30.0)
    )
    assert sleeps == [puncia_main.BACKOFF_BASE]


def test_fetch_headers_are_looked_up_case_insensitively(monkeypatch):
    """`_fetch` must return a mapping that answers `.get("X-Truncated")`
    correctly for a lowercase header source; a plain dict would not."""
    session = _FakeGetSession(
        [_FakeResponse(200, json_data=["a.com"], headers={"x-truncated": "true", "x-next-offset": "5"})]
    )

    data, headers = asyncio.run(
        puncia_main._fetch(session, "https://api.subdomain.center/?domain=x", {}, None, retries=0, timeout=30.0)
    )
    assert headers.get("X-Truncated") == "true"
    assert headers.get("X-Next-Offset") == "5"


def test_pagination_continues_when_server_sends_lowercase_headers(monkeypatch):
    """End-to-end version of the same check, through the real page-walker."""

    class _LowercaseFetch:
        def __init__(self, pages):
            self.pages = list(pages)

        async def __call__(self, session, url, headers, limiter, retries, timeout):
            page, extra_headers = self.pages.pop(0)
            raw = {"x-truncated": "true" if extra_headers.get("more") else "false"}
            if "next_offset" in extra_headers:
                raw["x-next-offset"] = str(extra_headers["next_offset"])
            return page, CIMultiDict(raw)

    fetch = _LowercaseFetch(
        [
            (["a.com", "b.com"], {"more": True, "next_offset": 2}),
            (["c.com"], {"more": False}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fetch)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com", "c.com"], (
        "pagination stopped after page 1 — the case-insensitivity bug is back"
    )


# --------------------------------------------------------------------------- #
# Pagination — page-walking logic (server responses are faked; no network)
# --------------------------------------------------------------------------- #

class FakeFetch:
    """Stand-in for `_fetch`: replays canned (data, headers) pages in order."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.urls: list = []

    async def __call__(self, session, url, headers, limiter, retries, timeout):
        self.urls.append(url)
        if not self.pages:
            raise AssertionError("fetched more pages than were queued")
        return self.pages.pop(0)


def _offset_of(url: str) -> str:
    for part in url.split("?", 1)[-1].split("&"):
        if part.startswith("offset="):
            return part.split("=", 1)[1]
    return ""


def test_no_truncated_header_short_page_stops_after_one_page(monkeypatch):
    """Without X-Truncated, a page shorter than the explicit page size is the
    last one; must not loop."""
    fake = FakeFetch([(["a.example.com", "b.example.com"], {"X-Result-Count": "2"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", 5, {}, None, 0, 30.0
        )
    )
    assert result == ["a.example.com", "b.example.com"]
    assert len(fake.urls) == 1, "a short page without a continue signal is the last page"


def test_no_truncated_header_full_page_walks_until_short_page(monkeypatch):
    """Without X-Truncated, a page as long as the requested page size means
    more rows may exist, so the walk continues."""
    fake = FakeFetch(
        [
            (["a.com", "b.com"], {"X-Result-Count": "2"}),
            (["c.com", "d.com"], {"X-Result-Count": "2"}),
            (["e.com"], {"X-Result-Count": "1"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", 2, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com", "c.com", "d.com", "e.com"]
    assert [_offset_of(u) for u in fake.urls] == ["0", "2", "4"]
    assert all("limit=2" in u for u in fake.urls)


def test_no_limit_sends_the_default_page_size_and_stops_on_a_short_page(monkeypatch):
    """With no --limit the walk sends its default page size itself on page
    one, so a small result is recognised as the last page at once."""
    fake = FakeFetch([(["a.example.com", "b.example.com"], {"X-Result-Count": "2"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.example.com", "b.example.com"]
    assert len(fake.urls) == 1, "a short page is the last page; no probe needed"
    assert f"limit={puncia_main.SUBDOMAIN_DEFAULT_PAGE}" in fake.urls[0]
    assert _offset_of(fake.urls[0]) == "0"


def test_no_limit_walk_repeats_the_default_page_size_on_every_page(monkeypatch):
    """The page size is sent on every page, and it is the one page one used."""
    fake = FakeFetch(
        [
            (["a.com"], {"X-Truncated": "true", "X-Next-Offset": "1"}),
            (["b.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com"]
    default = f"limit={puncia_main.SUBDOMAIN_DEFAULT_PAGE}"
    assert all(default in url for url in fake.urls)


def test_explicit_truncated_false_on_short_page_stops_after_one_page(monkeypatch):
    fake = FakeFetch([(["a.com"], {"X-Result-Count": "1", "X-Truncated": "false"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", 5, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com"]
    assert len(fake.urls) == 1


def test_truncated_false_on_nearly_full_page_is_not_trusted(monkeypatch):
    """A nearly full page is walked past even under `X-Truncated: false`,
    stepping by the rows served; the next window may re-serve the last row,
    which client-side de-duplication absorbs."""
    page_one = [f"h{i}.example.com" for i in range(199)]  # 200 asked, 199 served
    # The next window starts at 199 and re-serves page one's last row.
    page_two = [page_one[-1]] + [f"h{i}.example.com" for i in range(200, 350)]  # short: the end
    fake = FakeFetch(
        [
            (page_one, {"X-Result-Count": "199", "X-Truncated": "false"}),
            (page_two, {"X-Result-Count": "151", "X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "keyword", "example", "", "", 200, {}, None, 0, 30.0
        )
    )
    assert result == page_one + page_two[1:], "overlap must be collapsed, nothing lost"
    assert [_offset_of(u) for u in fake.urls] == ["0", "199"]


def test_explicit_truncated_false_on_short_page_without_limit_stops_at_once(monkeypatch):
    """No --limit, explicit `false`, one row against a 200k default page: last
    page, one request. Previously this cost a second (empty) request."""
    fake = FakeFetch([(["a.com"], {"X-Result-Count": "1", "X-Truncated": "false"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com"]
    assert len(fake.urls) == 1


def test_overlapping_pages_are_deduplicated_in_order(monkeypatch):
    """Consecutive windows may overlap; repeats are collapsed, order kept."""
    fake = FakeFetch(
        [
            (["a.com", "b.com", "c.com"], {"X-Truncated": "true", "X-Next-Offset": "3"}),
            (["c.com", "d.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com", "c.com", "d.com"]


def test_truncated_true_with_next_offset_walks_to_next_page(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com", "b.com"], {"X-Truncated": "true", "X-Next-Offset": "2"}),
            (["c.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com", "c.com"]
    assert len(fake.urls) == 2
    assert _offset_of(fake.urls[0]) == "0"
    assert _offset_of(fake.urls[1]) == "2"


def test_truncated_true_without_next_offset_falls_back_to_result_count(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com", "b.com", "c.com"], {"X-Truncated": "true", "X-Result-Count": "3"}),
            (["d.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com", "b.com", "c.com", "d.com"]
    assert _offset_of(fake.urls[1]) == "3"


def test_empty_page_stops_pagination_even_if_marked_truncated(monkeypatch):
    fake = FakeFetch([([], {"X-Truncated": "true", "X-Next-Offset": "0"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == []
    assert len(fake.urls) == 1


def test_non_advancing_offset_stops_instead_of_looping_forever(monkeypatch):
    """A repeated X-Next-Offset must not spin."""
    fake = FakeFetch(
        [(["a.com"], {"X-Truncated": "true", "X-Next-Offset": "0"}) for _ in range(5)]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com"]
    assert len(fake.urls) == 1


def test_non_list_first_page_is_returned_as_is(monkeypatch):
    """An error payload (bad match, etc.) on page 1 must surface, not vanish."""
    error_payload = {"error": "unknown match"}
    fake = FakeFetch([(error_payload, {})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "keyword", "blog", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == error_payload


def test_non_list_mid_walk_raises_instead_of_silently_dropping_data(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com"], {"X-Truncated": "true", "X-Next-Offset": "1"}),
            ({"unexpected": "shape"}, {}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    with pytest.raises(PunciaError, match="non-list response mid-walk"):
        asyncio.run(
            puncia_main._fetch_all_pages(
                None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
            )
        )


def test_pagination_gives_up_after_max_pages(monkeypatch):
    monkeypatch.setattr(puncia_main, "MAX_PAGES", 3)
    pages = [
        ([f"host{i}.com"], {"X-Truncated": "true", "X-Next-Offset": str(i + 1)})
        for i in range(10)
    ]
    fake = FakeFetch(pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    with pytest.raises(PunciaError, match="did not complete within 3 pages"):
        asyncio.run(
            puncia_main._fetch_all_pages(
                None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
            )
        )


def test_on_page_callback_reports_progress(monkeypatch):
    fake = FakeFetch(
        [
            (["a.com", "b.com"], {"X-Truncated": "true", "X-Next-Offset": "2"}),
            (["c.com"], {"X-Truncated": "false"}),
        ]
    )
    monkeypatch.setattr(puncia_main, "_fetch", fake)
    calls = []

    asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0,
            on_page=lambda page, rows: calls.append((page, rows)),
        )
    )
    assert calls == [(1, 2), (2, 3)]


# --------------------------------------------------------------------------- #
# Pagination — query_api's auto-paginate vs. manual-page decision
# --------------------------------------------------------------------------- #

def test_query_api_auto_paginates_when_authenticated_and_no_offset(monkeypatch):
    called = {}

    async def fake_fetch_all_pages(session, mode, query, match, scope, limit,
                                    headers, limiter, retries, timeout, on_page=None,
                                    crawl=False, on_crawl=None):
        called["used"] = True
        return ["a.com"]

    async def fake_fetch(*a, **k):
        called["single_page_used"] = True
        return ["a.com"], {}

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)

    result = asyncio.run(query_api("subdomain", "example.com", apikey="ARPS-x"))
    assert result == ["a.com"]
    assert called.get("used") is True
    assert "single_page_used" not in called


def test_query_api_uses_single_page_when_offset_given(monkeypatch):
    called = {}

    async def fake_fetch_all_pages(*a, **k):
        called["auto_used"] = True
        return []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        called["single_page_used"] = True
        return ["a.com"], {"X-Truncated": "true", "X-Next-Offset": "50"}

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)

    seen_headers = {}
    result = asyncio.run(
        query_api(
            "subdomain", "example.com", apikey="ARPS-x", offset=0,
            on_headers=seen_headers.update,
        )
    )
    assert result == ["a.com"]
    assert called.get("single_page_used") is True
    assert "auto_used" not in called
    assert seen_headers["X-Next-Offset"] == "50"


def test_query_api_does_not_auto_paginate_without_a_key(monkeypatch):
    """Anonymous requests are never paginated by puncia."""
    called = {}

    async def fake_fetch_all_pages(*a, **k):
        called["auto_used"] = True
        return []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        called["single_page_used"] = True
        return ["a.com"], {}

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)

    result = asyncio.run(query_api("subdomain", "example.com", apikey=""))
    assert result == ["a.com"]
    assert called.get("single_page_used") is True
    assert "auto_used" not in called


def test_query_api_validates_every_argument_before_walking(monkeypatch):
    """The page walkers rebuild URLs with only the arguments they use, so a
    `match` handed to `nuclei` (or `crawl` to `replica`) used to be dropped
    silently. It must be rejected like it is on the single-request path."""
    async def fake_fetch(*a, **k):
        raise AssertionError("must not reach the network with invalid arguments")

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    with pytest.raises(PunciaError, match="does not support --match"):
        asyncio.run(query_api("nuclei", "candidates", apikey="ARPS-x", match="exact"))
    with pytest.raises(PunciaError, match="does not support --crawl"):
        asyncio.run(query_api("replica", "example.com", apikey="ARPS-x", crawl=True))


def test_anonymous_query_api_calls_share_one_limiter_per_host(monkeypatch):
    """Two back-to-back anonymous calls from one process share the per-IP
    budget, so they must share a limiter rather than each bringing a fresh
    one that lets both fire at once."""
    seen = []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        seen.append(limiter)
        return ["a.com"], CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    asyncio.run(query_api("subdomain", "example.com"))
    asyncio.run(query_api("replica", "example.com"))
    asyncio.run(query_api("exploit", "CVE-2021-3450"))
    assert seen[0] is seen[1] is puncia_main._DEFAULT_LIMITERS[puncia_main.SUBDOMAIN_HOST]
    assert seen[2] is puncia_main._DEFAULT_LIMITERS[puncia_main.EXPLOIT_HOST]
    assert seen[2] is not seen[0]


def test_query_api_does_not_auto_paginate_exploit_observer_modes(monkeypatch):
    """Only Subdomain Center modes paginate; exploit takes a single hit."""
    called = {}

    async def fake_fetch_all_pages(*a, **k):
        called["auto_used"] = True
        return []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        called["single_page_used"] = True
        return {"description": "..."}, {}

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)

    result = asyncio.run(query_api("exploit", "CVE-2021-3450", apikey="ARPS-x"))
    assert result == {"description": "..."}
    assert called.get("single_page_used") is True
    assert "auto_used" not in called


# --------------------------------------------------------------------------- #
# CLI argument validation
# --------------------------------------------------------------------------- #

def test_non_negative_int_accepts_zero_and_positive():
    assert puncia_main._non_negative_int("0") == 0
    assert puncia_main._non_negative_int("100000") == 100000


def test_non_negative_int_rejects_negative():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        puncia_main._non_negative_int("-1")


@pytest.mark.parametrize(
    "flag, value",
    [("--limit", "0"), ("--retries", "-1"), ("--concurrency", "0"), ("--timeout", "0"),
     ("--timeout", "-3"), ("--timeout", "nan")],
)
def test_cli_rejects_unusable_numeric_flags(flag, value, capsys):
    """A negative --retries meant zero attempts and a bare 'request failed';
    --concurrency 0 a dead semaphore; --timeout 0 no timeout at all."""
    with pytest.raises(SystemExit) as exc:
        asyncio.run(puncia_main.main(["subdomain", "example.com", flag, value]))
    assert exc.value.code == 2


def test_cli_storekey_rejects_an_empty_key(tmp_path, capsys):
    code = asyncio.run(puncia_main.main(["storekey", "   "]))
    assert code == 1
    assert "non-empty API key" in capsys.readouterr().err
    assert not (tmp_path / ".puncia").exists()


def test_cli_bulk_warns_about_flags_it_ignores(monkeypatch, tmp_path, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return ["a.example.com"], CIMultiDict({"X-Truncated": "false"})

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps({"subdomain": ["example.com"]}))
    code = asyncio.run(puncia_main.main(
        ["bulk", str(targets), str(tmp_path / "out"), "--match", "exact", "--offset", "0",
         "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    err = " ".join(capsys.readouterr().err.split())
    assert "--match, --offset do not apply to bulk mode" in err
    assert (tmp_path / "out" / "subdomain" / "example.com.json").exists()


# --------------------------------------------------------------------------- #
# Rich markup — untrusted text must be printed, never parsed
# --------------------------------------------------------------------------- #

def test_bulk_failure_summary_survives_markup_in_a_query(monkeypatch, tmp_path, capsys):
    """Regression: an SBOM component named `pkg[/]@1.0` that failed made rich
    raise MarkupError while printing the failure line, aborting the whole run
    with a traceback instead of a summary."""
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        raise PunciaError("HTTP 500: [bold]boom[/bold]")

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    failures = asyncio.run(puncia_main.process_bulk(
        {"exploit": ["pkg[/]@1.0", "[link=https://evil]x[/link]@2"]}, tmp_path,
        apikey="ARPS-x", show_progress=False,
    ))
    assert failures == 2
    err = capsys.readouterr().err
    assert "pkg[/]@1.0" in err and "[bold]boom[/bold]" in err


def test_cli_error_text_with_markup_is_printed_verbatim(monkeypatch, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        raise PunciaError("HTTP 400: invalid domain: '[/]x'")

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(["subdomain", "[/]x", "--api-key", "ARPS-x", "--quiet"]))
    assert code == 1
    assert "invalid domain: '[/]x'" in capsys.readouterr().err


def test_bulk_warnings_survive_markup_in_mode_names(tmp_path, capsys):
    with pytest.raises(PunciaError, match="no valid queries"):
        asyncio.run(puncia_main.process_bulk({"[/bold]": ["x"]}, tmp_path, show_progress=False))
    assert "skipping unknown mode" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# SBOM parsing
# --------------------------------------------------------------------------- #

def test_sbom_extracts_metadata_and_components():
    sbom = {
        "metadata": {"component": {"name": "app", "version": "1.0"}},
        "components": [
            {"name": "log4j-core", "version": "2.14.1"},
            {"name": "openssl", "version": "1.1.1h"},
        ],
    }
    assert sbom_process(sbom) == ["app@1.0", "log4j-core@2.14.1", "openssl@1.1.1h"]


def test_sbom_skips_incomplete_and_malformed_entries():
    sbom = {
        "metadata": {},
        "components": [
            {"name": "no-version"},
            {"version": "no-name"},
            "not-a-dict",
            {"name": "ok", "version": "1.0"},
            {"name": 5, "version": 6},
        ],
    }
    assert sbom_process(sbom) == ["ok@1.0"]


def test_sbom_tolerates_null_sections():
    assert sbom_process({"metadata": None, "components": None}) == []


def test_sbom_that_is_not_an_object_yields_nothing_instead_of_crashing():
    assert sbom_process(["not", "a", "bom"]) == []
    assert sbom_process("bom") == []
    assert sbom_process({"metadata": {"component": "x"}, "components": [{"name": "a", "version": "1"}]}) == ["a@1"]


def test_cli_sbom_without_components_is_an_input_error(tmp_path, capsys):
    bom = tmp_path / "bom.json"
    bom.write_text("[]")
    code = asyncio.run(puncia_main.main(["sbom", str(bom), str(tmp_path / "out")]))
    assert code == 1
    assert "expected a CycloneDX document" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Bulk planning
# --------------------------------------------------------------------------- #

def test_plan_bulk_deduplicates(tmp_path):
    jobs, _ = plan_bulk({"exploit": ["CVE-1", "CVE-1", "CVE-2"]}, tmp_path.resolve())
    assert len(jobs) == 2


def test_plan_bulk_warns_on_unknown_mode(tmp_path):
    jobs, warnings = plan_bulk({"chat": ["hello"]}, tmp_path.resolve())
    assert jobs == []
    assert any("unknown mode" in warning for warning in warnings)


def test_plan_bulk_rejects_non_list_and_non_string(tmp_path):
    jobs, warnings = plan_bulk(
        {"exploit": "CVE-1", "subdomain": [123, "ok.com"]}, tmp_path.resolve()
    )
    assert [job[1] for job in jobs] == ["ok.com"]
    assert len(warnings) == 2


def test_plan_bulk_scrubbed_names_never_share_a_file(tmp_path):
    """`a/b@1` and `a:b@1` both scrub to `a_b@1`; without a disambiguator the
    second result silently overwrote the first."""
    jobs, warnings = plan_bulk({"exploit": ["a/b@1", "a:b@1", "a_b@1"]}, tmp_path.resolve())
    destinations = [job[2] for job in jobs]
    assert len(jobs) == 3 and len(set(destinations)) == 3
    assert warnings == []
    # The untouched name keeps its plain filename; only altered ones carry a hash.
    assert (tmp_path.resolve() / "exploit" / "a_b@1.json") in destinations


def test_plan_bulk_case_variants_get_distinct_files(tmp_path):
    """macOS/Windows filesystems are case-insensitive; distinct queries must
    not map onto one file there."""
    jobs, _ = plan_bulk({"exploit": ["CVE-2021-1", "cve-2021-1"]}, tmp_path.resolve())
    assert len(jobs) == 2
    names = {str(job[2]).lower() for job in jobs}
    assert len(names) == 2


def test_plan_bulk_strips_whitespace_and_deduplicates_on_it(tmp_path):
    jobs, _ = plan_bulk({"exploit": ["CVE-1", " CVE-1 "]}, tmp_path.resolve())
    assert [job[1] for job in jobs] == ["CVE-1"]


def test_windows_reserved_device_names_are_not_used_verbatim(tmp_path):
    root = tmp_path.resolve()
    for name in ("CON", "nul", "COM1", "Lpt9"):
        destination = safe_output_path(root, "exploit", name)
        assert destination is not None
        assert destination.stem.lower() != name.lower()
        assert destination.parent == root / "exploit"


def test_process_bulk_with_no_valid_queries_is_an_error(tmp_path, capsys):
    """Exit 0 with nothing written hid broken input files in CI."""
    with pytest.raises(PunciaError, match="no valid queries"):
        asyncio.run(puncia_main.process_bulk({"chat": ["hi"]}, tmp_path, show_progress=False))
    assert not (tmp_path / "chat").exists()


def test_write_failures_are_puncia_errors(tmp_path):
    """So a bulk job that cannot write its file is recorded as that job's
    failure instead of an OSError escaping asyncio.gather and killing the run."""
    blocker = tmp_path / "dir.json"
    blocker.mkdir()
    with pytest.raises(PunciaError, match="cannot write"):
        asyncio.run(puncia_main.write_json(blocker, {"a": 1}))
    with pytest.raises(PunciaError, match="cannot write"):
        asyncio.run(puncia_main.write_csv(blocker, {"candidates": []}))


def test_process_bulk_records_a_write_failure_and_finishes(monkeypatch, tmp_path, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return {"description": "x"}, CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    root = tmp_path.resolve()
    (root / "exploit").mkdir(parents=True)
    (root / "exploit" / "CVE-1.json").mkdir()  # the destination is a directory
    failures = asyncio.run(puncia_main.process_bulk(
        {"exploit": ["CVE-1", "CVE-2"]}, root, apikey="ARPS-x", show_progress=False,
    ))
    assert failures == 1
    assert (root / "exploit" / "CVE-2.json").is_file()
    assert "cannot write" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

def test_rate_limiter_spaces_out_concurrent_callers():
    """Concurrent tasks must be serialised, not allowed to sleep in parallel."""
    limiter = RateLimiter(0.2)

    async def scenario():
        start = time.monotonic()
        await asyncio.gather(*(limiter.acquire() for _ in range(3)))
        return time.monotonic() - start

    elapsed = asyncio.run(scenario())
    assert elapsed >= 0.4, f"three acquisitions finished in {elapsed:.3f}s"


def test_zero_interval_limiter_does_not_sleep():
    limiter = RateLimiter(0.0)

    async def scenario():
        start = time.monotonic()
        await asyncio.gather(*(limiter.acquire() for _ in range(50)))
        return time.monotonic() - start

    assert asyncio.run(scenario()) < 0.1


# --------------------------------------------------------------------------- #
# Key storage
# --------------------------------------------------------------------------- #

def test_key_roundtrip_and_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("PUNCIA_API_KEY", raising=False)

    asyncio.run(store_key("  ARPS-secret  "))
    assert asyncio.run(read_key()) == "ARPS-secret"

    key_file = tmp_path / ".puncia"
    if os.name == "posix":
        mode = stat.S_IMODE(key_file.stat().st_mode)
        assert mode == 0o600, f"key file is {oct(mode)}, expected 0o600"


def test_env_var_takes_precedence_over_stored_key(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    asyncio.run(store_key("stored"))
    monkeypatch.setenv("PUNCIA_API_KEY", "from-env")
    assert asyncio.run(read_key()) == "from-env"


def test_missing_key_file_yields_empty_string(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("PUNCIA_API_KEY", raising=False)
    assert asyncio.run(read_key()) == ""


# --------------------------------------------------------------------------- #
# Exploit Observer nuclei candidates — filters, paging, CSV export
# --------------------------------------------------------------------------- #

def _candidate(cve, **over):
    row = {
        "cve": cve, "vedas_id": "V-" + cve, "priority": 0.27, "feasibility": 0.9, "impact": 0.3,
        "shape": {"protocol": "http", "method": "active", "authenticated": False},
        "product": "wordpress:wordpress", "platform": None, "cwe": ["CWE-79"],
        "cvss": "CVSS:3.1/AV:N", "vedas": 0.04, "epss": 0.004, "kev": False,
        "poc_sources": ["GITHUB/a/b", "EDB-1"], "portable_templates": [],
        "test_environments": ["vulhub"], "sibling_templates": ["PD/http/cves/2024/x"],
        "reasons": ["cwe CWE-79 (3.1x base template rate)", "exploit github (9.7x)"],
    }
    row.update(over)
    return row


def test_nuclei_candidates_url_carries_filters_and_paging():
    url = build_request("nuclei", "candidates", limit=50, offset=100,
                        filters={"platform": "wordpress", "kev": "true"})
    assert url.startswith("https://api.exploit.observer/nuclei/candidates?")
    assert "platform=wordpress" in url and "kev=true" in url
    assert "limit=50" in url and "offset=100" in url


def test_nuclei_candidates_bare_url_has_no_query_string():
    assert build_request("nuclei", "candidates") == "https://api.exploit.observer/nuclei/candidates"


def test_nuclei_only_accepts_the_candidates_query():
    with pytest.raises(PunciaError, match="expected one of: candidates"):
        build_request("nuclei", "everything")


def test_nuclei_unknown_filter_key_fails_fast():
    with pytest.raises(PunciaError, match="unknown filter"):
        build_request("nuclei", "candidates", filters={"severity": "high"})


def test_filters_rejected_for_modes_without_them():
    with pytest.raises(PunciaError, match="does not support --filter"):
        build_request("exploit", "CVE-2021-44228", filters={"kev": "true"})


@pytest.mark.parametrize("limit", [0, 1001])
def test_nuclei_limit_is_bounded_by_the_page_cap(limit):
    with pytest.raises(PunciaError, match="between 1 and 1000"):
        build_request("nuclei", "candidates", limit=limit)


def test_nuclei_offset_does_not_require_limit():
    # nuclei needs no --limit alongside --offset
    assert "offset=200" in build_request("nuclei", "candidates", offset=200)


def test_nuclei_walks_every_page_and_merges(monkeypatch):
    pages = {
        0: {"generated": "g", "total": 3, "offset": 0, "limit": 2,
            "candidates": [_candidate("CVE-2026-0001"), _candidate("CVE-2026-0002")]},
        2: {"generated": "g", "total": 3, "offset": 2, "limit": 2,
            "candidates": [_candidate("CVE-2026-0003")]},
    }
    seen_urls = []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        seen_urls.append(url)
        offset = int(url.split("offset=")[1].split("&")[0])
        return pages[offset], CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    result = asyncio.run(query_api("nuclei", "candidates", apikey="ARPS-x", limit=2,
                                   filters={"kev": "true"}))
    assert [r["cve"] for r in result["candidates"]] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert result["total"] == 3 and result["offset"] == 0
    assert len(seen_urls) == 2 and all("kev=true" in u for u in seen_urls)


def test_nuclei_without_a_key_returns_the_empty_body_after_one_request(monkeypatch):
    calls = []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        calls.append(url)
        return {}, CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    monkeypatch.setattr(puncia_main.RateLimiter, "acquire", lambda self: asyncio.sleep(0))
    assert asyncio.run(query_api("nuclei", "candidates")) == {}
    assert len(calls) == 1


def test_nuclei_with_offset_fetches_exactly_one_page(monkeypatch):
    calls = []

    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        calls.append(url)
        return {"total": 9, "candidates": [_candidate("CVE-2026-0009")]}, CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    asyncio.run(query_api("nuclei", "candidates", apikey="ARPS-x", offset=8))
    assert len(calls) == 1 and "offset=8" in calls[0]


def test_candidates_csv_has_one_row_per_cve_in_ranked_order():
    import csv as csv_module
    from puncia import NUCLEI_CSV_COLUMNS, candidates_to_csv

    body = {"candidates": [_candidate("CVE-2026-0001"), _candidate("CVE-2026-0002", kev=True)]}
    rows = list(csv_module.DictReader(candidates_to_csv(body).splitlines()))
    assert list(rows[0]) == list(NUCLEI_CSV_COLUMNS)
    assert [r["cve"] for r in rows] == ["CVE-2026-0001", "CVE-2026-0002"]
    first = rows[0]
    assert first["protocol"] == "http" and first["method"] == "active"
    assert first["authenticated"] == "false" and rows[1]["kev"] == "true"
    assert first["poc_sources"] == "GITHUB/a/b;EDB-1"
    assert first["reasons"] == "cwe CWE-79 (3.1x base template rate) | exploit github (9.7x)"
    assert first["platform"] == ""


def test_candidates_csv_carries_the_buildability_axes_and_ecosystem():
    """`ecosystem` and every `shape` key land in their own CSV columns."""
    import csv as csv_module
    from puncia import candidates_to_csv

    row = _candidate(
        "CVE-2026-0001", ecosystem="npm",
        shape={"protocol": "unknown", "method": "active", "authenticated": False,
               "likely_http": True, "surface": "unknown", "state_change": "read", "xss_kind": None},
    )
    rows = list(csv_module.DictReader(candidates_to_csv({"candidates": [row]}).splitlines()))
    first = rows[0]
    assert first["ecosystem"] == "npm"
    assert first["likely_http"] == "true" and first["state_change"] == "read"
    assert first["surface"] == "unknown" and first["xss_kind"] == ""
    assert first["protocol"] == "unknown" and first["method"] == "active"


def test_candidates_csv_skips_non_object_rows():
    from puncia import candidates_to_csv

    text = candidates_to_csv({"candidates": ["garbage", None, _candidate("CVE-2026-0002")]})
    assert text.count("\n") == 2 and "CVE-2026-0002" in text
    assert candidates_to_csv({"candidates": "not-a-list"}).count("\n") == 1


def test_candidates_csv_neutralises_spreadsheet_formulas():
    from puncia import candidates_to_csv

    body = {"candidates": [_candidate("CVE-2026-0001", product='=HYPERLINK("http://x","y")',
                                      poc_sources=["@evil"])]}
    text = candidates_to_csv(body)
    assert "'=HYPERLINK" in text and "'@evil" in text


def test_candidates_csv_of_an_unauthenticated_empty_body_is_header_only():
    from puncia import candidates_to_csv

    text = candidates_to_csv({})
    assert text.startswith("cve,") and text.count("\n") == 1


def test_query_api_writes_csv_to_the_output_file(monkeypatch, tmp_path):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return {"total": 1, "candidates": [_candidate("CVE-2026-0001")]}, CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    out = tmp_path / "nuclei.csv"
    asyncio.run(query_api("nuclei", "candidates", out, apikey="ARPS-x", output_format="csv"))
    lines = out.read_text().splitlines()
    assert lines[0].startswith("cve,vedas_id,priority") and lines[1].startswith("CVE-2026-0001,")


def test_csv_output_is_rejected_for_other_modes():
    with pytest.raises(PunciaError, match="only supported for mode 'nuclei'"):
        asyncio.run(query_api("exploit", "CVE-2021-44228", output_format="csv"))


def test_cli_csv_output_path_implies_csv_and_stdout_gets_csv(monkeypatch, tmp_path, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return {"total": 1, "candidates": [_candidate("CVE-2026-0001")]}, CIMultiDict()

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    out = tmp_path / "out.csv"
    code = asyncio.run(puncia_main.main(
        ["nuclei", "candidates", str(out), "--api-key", "ARPS-x", "--quiet",
         "--filter", "platform=wordpress"]))
    assert code == 0
    assert out.read_text().startswith("cve,")
    assert capsys.readouterr().out.startswith("cve,")


def test_cli_rejects_a_malformed_filter(capsys):
    code = asyncio.run(puncia_main.main(["nuclei", "candidates", "--filter", "kev"]))
    assert code == 1
    assert "KEY=VALUE" in capsys.readouterr().err


def test_cli_manual_page_warns_when_full_sized_despite_truncated_false(monkeypatch, capsys):
    """A --limit 200 manual page that returns 199 rows + `X-Truncated: false`
    is treated as possibly incomplete, and the hint steps by the 199 rows
    served (the next page may overlap by a row; it can never skip one)."""
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        rows = [f"h{i}.example.com" for i in range(199)]
        return rows, CIMultiDict({"X-Result-Count": "199", "X-Truncated": "false"})

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(
        ["keyword", "example", "--offset", "0", "--limit", "200", "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    err = " ".join(capsys.readouterr().err.split())  # rich wraps at console width
    assert "full-sized" in err
    assert "--offset 199 --limit 200" in err


def test_cli_manual_page_without_limit_hints_the_default_page_size(monkeypatch, capsys):
    """`--offset 0` with no --limit: the hint repeats puncia's default page
    size, since offset>0 requires limit."""
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return ["a.example.com"], CIMultiDict(
            {"X-Result-Count": "1", "X-Truncated": "true", "X-Next-Offset": "1"}
        )

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(
        ["subdomain", "example.com", "--offset", "0", "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    err = " ".join(capsys.readouterr().err.split())
    assert f"--offset 1 --limit {puncia_main.SUBDOMAIN_DEFAULT_PAGE}" in err


def test_cli_nuclei_manual_page_hint_comes_from_the_body_not_subdomain_headers(monkeypatch, capsys):
    """The nuclei hint comes from the body's offset/candidates/total, never
    from an `X-Result-Count` header."""
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        body = {"generated": "g", "total": 2500, "offset": 0, "limit": 2,
                "candidates": [_candidate("CVE-2026-0001"), _candidate("CVE-2026-0002")]}
        return body, CIMultiDict({"X-Result-Count": "2500"})

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(
        ["nuclei", "candidates", "--offset", "0", "--limit", "2", "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    err = " ".join(capsys.readouterr().err.split())
    assert "2 of 2500 candidates seen" in err
    assert "--offset 2 --limit 2" in err
    assert "--offset 2500" not in err


def test_cli_nuclei_last_manual_page_prints_no_hint(monkeypatch, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        body = {"total": 3, "offset": 2, "limit": 2, "candidates": [_candidate("CVE-2026-0003")]}
        return body, CIMultiDict({"X-Result-Count": "3"})

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(
        ["nuclei", "candidates", "--offset", "2", "--limit", "2", "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    assert "continue with" not in capsys.readouterr().err


def test_cli_manual_page_stays_quiet_on_a_clearly_short_last_page(monkeypatch, capsys):
    async def fake_fetch(session, url, headers, limiter, retries, timeout):
        return ["a.example.com"], CIMultiDict({"X-Result-Count": "1", "X-Truncated": "false"})

    monkeypatch.setattr(puncia_main, "_fetch", fake_fetch)
    code = asyncio.run(puncia_main.main(
        ["keyword", "example", "--offset", "0", "--limit", "200", "--api-key", "ARPS-x", "--quiet"]
    ))
    assert code == 0
    assert "continue with" not in capsys.readouterr().err


def test_cli_never_echoes_crawl_source_names(monkeypatch, capsys):
    async def fake_fetch_all_pages(session, mode, query, match, scope, limit, headers, limiter,
                                   retries, timeout, on_page=None, crawl=False, on_crawl=None):
        on_crawl(CIMultiDict({"X-Crawl-Status": "partial", "X-Crawl-New-Count": "3",
                              "X-Crawl-Pending": "source-a,source-b", "X-Crawl-Failed": "source-c"}))
        return ["a.example.com"]

    monkeypatch.setattr(puncia_main, "_fetch_all_pages", fake_fetch_all_pages)
    code = asyncio.run(puncia_main.main(["subdomain", "example.com", "--crawl", "--api-key", "ARPS-x", "--quiet"]))
    assert code == 0
    captured = capsys.readouterr()
    for name in ("source-a", "source-b", "source-c"):
        assert name not in captured.err and name not in captured.out
    assert "crawl: partial, 3 newly discovered" in captured.err
    assert "more results still coming" in captured.err
