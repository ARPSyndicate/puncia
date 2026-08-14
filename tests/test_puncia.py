"""Unit tests for puncia. Everything here is offline — no API calls."""

import asyncio
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

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
    for mode in ("subdomain", "replica", "exploit", "enrich"):
        with pytest.raises(PunciaError, match="does not support --domain"):
            build_request(mode, "example.com", scope="other.com")


def test_enrich_sets_enrich_flag():
    url = build_request("enrich", "CVE-2021-44228")
    assert "enrich=True" in url and "keyword=CVE-2021-44228" in url


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
    for mode in ("exploit", "enrich", "noncve"):
        query = "exploitable" if mode == "noncve" else "CVE-2021-3450"
        with pytest.raises(PunciaError, match="does not support pagination"):
            build_request(mode, query, limit=100)
        with pytest.raises(PunciaError, match="does not support pagination"):
            build_request(mode, query, offset=0)


def test_negative_limit_and_offset_rejected():
    with pytest.raises(PunciaError, match="--limit must be >= 0"):
        build_request("subdomain", "example.com", limit=-1)
    with pytest.raises(PunciaError, match="--offset must be >= 0"):
        build_request("subdomain", "example.com", offset=-1)


def test_offset_zero_is_sent_explicitly_not_omitted():
    """offset=0 is a legitimate explicit value, distinct from "no offset"."""
    url = build_request("subdomain", "example.com", offset=0)
    assert "offset=0" in url


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


def test_no_truncated_header_stops_after_one_page(monkeypatch):
    """Today's live API omits X-Truncated on most endpoints; must not loop."""
    fake = FakeFetch([(["a.example.com", "b.example.com"], {"X-Result-Count": "2"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.example.com", "b.example.com"]
    assert len(fake.urls) == 1, "must not request a second page without a continue signal"


def test_explicit_truncated_false_stops_after_one_page(monkeypatch):
    fake = FakeFetch([(["a.com"], {"X-Result-Count": "1", "X-Truncated": "false"})])
    monkeypatch.setattr(puncia_main, "_fetch", fake)

    result = asyncio.run(
        puncia_main._fetch_all_pages(
            None, "subdomain", "example.com", "", "", None, {}, None, 0, 30.0
        )
    )
    assert result == ["a.com"]
    assert len(fake.urls) == 1


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
    """A server bug that repeats the same X-Next-Offset must not spin."""
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
                                    headers, limiter, retries, timeout, on_page=None):
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
    """Anonymous requests ignore limit/offset server-side; don't walk pages."""
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


def test_query_api_does_not_auto_paginate_exploit_observer_modes(monkeypatch):
    """Only Subdomain Center modes paginate; exploit/enrich take a single hit."""
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
