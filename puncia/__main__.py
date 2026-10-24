"""Panthera(P.)uncia — subdomain recon, brand-impersonation & exploit intelligence CLI.

Thin, well-behaved client for two A.R.P. Syndicate APIs:

* Subdomain Center  — subdomain enumeration, shadow IT, lookalike/typosquat domains
* Exploit Observer  — vulnerability & exploit intelligence, SBOM scanning
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import hashlib
import json
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence
from urllib.parse import quote, urlencode

import aiohttp
from aiofiles import open as aio_open
from multidict import CIMultiDict
from rich.console import Console
from rich.json import JSON
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .__about__ import __version__

# Result data goes to stdout; everything else (banner, progress, warnings, errors)
# goes to stderr, so `puncia subdomain example.com > out.json` yields clean JSON.
out_console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

SUBDOMAIN_API = "https://api.subdomain.center/"
EXPLOIT_API = "https://api.exploit.observer/"

SUBDOMAIN_HOST = "subdomain.center"
EXPLOIT_HOST = "exploit.observer"

#: Minimum seconds between unauthenticated requests, per host. Not applied
#: when an API key is present, nor to static pseudo-queries (`_is_static_query`).
FREE_TIER_INTERVAL = {SUBDOMAIN_HOST: 13.0, EXPLOIT_HOST: 31.0}

DEFAULT_TIMEOUT = 60.0
DEFAULT_RETRIES = 2
DEFAULT_CONCURRENCY = 10
BACKOFF_BASE = 2.0

#: Hard ceiling on pages walked for one query, so a walk that never sees a
#: stop signal (or whose offset stops advancing) cannot run forever.
MAX_PAGES = 10_000

#: Page size the automatic Subdomain Center walk sends when the caller gives
#: no ``limit``, so every request of a walk carries the same explicit page
#: size; and the largest ``limit`` puncia accepts for those modes.
SUBDOMAIN_DEFAULT_PAGE = 200_000
SUBDOMAIN_MAX_PAGE = 1_000_000

#: A page within this fraction of the requested page size counts as *full*
#: and is walked past whether or not the response flags more results; only a
#: clearly short page, or an empty one, ends a walk on its own.
PAGE_FULL_TOLERANCE = 0.10

#: Above this many bytes of rendered JSON, stdout output skips rich's syntax
#: highlighting even on a terminal: the highlighter re-parses and regex-scans
#: the whole document, which turns a 200k-row result into a multi-second
#: stall for no benefit (nobody reads 10 MB of coloured JSON by eye).
RICH_JSON_MAX_BYTES = 2_000_000

#: Characters that could escape a path segment. Any query that becomes a
#: filename (SBOM component names, bulk input) is scrubbed of these first.
UNSAFE_PATH_CHARS = re.compile(r"[\\/:\x00-\x1f\x7f]")
#: Names Windows reserves for devices; `CON.json` is still the console there.
WINDOWS_RESERVED_NAMES = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])$", re.IGNORECASE)
#: Leave room for the ".json" suffix and a disambiguating hash under NAME_MAX.
MAX_FILENAME_STEM = 200


class PunciaError(Exception):
    """Raised when a request cannot be completed or the input is invalid."""


@dataclass(frozen=True)
class Mode:
    """Declarative description of one CLI mode / API endpoint."""

    url: str
    host: str
    param: str = ""  # query-string parameter carrying the user's value
    engine: str = ""  # Subdomain Center clustering engine
    matches: tuple = ()  # permitted `match` values ( () == unsupported )
    values: tuple = ()  # permitted values for path-based modes
    scope_param: str = ""  # optional secondary param narrowing the search
    paid: bool = False
    crawl_capable: bool = False  # supports --crawl
    filters: tuple = ()  # permitted --filter keys ( () == unsupported )
    pageable: bool = False  # paged with limit/offset, continuation read from the body
    help: str = ""


#: Filter keys `nuclei candidates` accepts. Only the key is checked
#: client-side, so a typo in a key fails fast; values are passed through.
NUCLEI_FILTERS = (
    "min_feasibility", "vendor", "product", "platform", "cwe", "method",
    "protocol", "kev", "poc", "portable",
)
#: `/nuclei/candidates` serves at most this many rows per page.
NUCLEI_MAX_PAGE = 1000

MODES: dict[str, Mode] = {
    "subdomain": Mode(
        SUBDOMAIN_API,
        SUBDOMAIN_HOST,
        param="domain",
        crawl_capable=True,
        help="subdomains of a domain (cuttlefish engine) — attack surface & shadow IT",
    ),
    "replica": Mode(
        SUBDOMAIN_API,
        SUBDOMAIN_HOST,
        param="domain",
        engine="octopus",
        matches=("prefix", "exact", "substring"),
        help="lookalike/typosquat domains sharing a brand (octopus engine)",
    ),
    "keyword": Mode(
        SUBDOMAIN_API,
        SUBDOMAIN_HOST,
        param="keyword",
        engine="ammonites",
        matches=("exact", "prefix"),
        scope_param="domain",
        help="hosts carrying a keyword, optionally scoped with --domain (ammonites engine)",
    ),
    "exploit": Mode(
        EXPLOIT_API,
        EXPLOIT_HOST,
        param="keyword",
        matches=("substring", "prefix", "exact"),
        help="vulnerability/exploit intelligence for an identifier or product",
    ),
    "noncve": Mode(
        EXPLOIT_API + "noncve/",
        EXPLOIT_HOST,
        values=("browser", "china", "russia", "europe", "exploitable"),
        paid=True,
        help="non-CVE identifiers clustered by VEDAS group (requires an API key)",
    ),
    "nuclei": Mode(
        EXPLOIT_API + "nuclei/",
        EXPLOIT_HOST,
        values=("candidates",),
        filters=NUCLEI_FILTERS,
        pageable=True,
        paid=True,
        help="CVEs with no nuclei template that look templatable, ranked (requires an API key)",
    ),
}

#: Pseudo-queries that dispatch to a static, unauthenticated, unlimited
#: endpoint instead of the mode's normal parameterized query. Keyed by
#: (mode, query) since the same "^HEALTH" spelling means a different URL
#: depending on which API the mode belongs to.
STATIC_ENDPOINTS: dict[tuple, str] = {
    ("subdomain", "^HEALTH"): SUBDOMAIN_API + "health",
    ("exploit", "^WATCHLIST_IDES"): EXPLOIT_API + "watchlist/identifiers",
    ("exploit", "^WATCHLIST_INFO"): EXPLOIT_API + "watchlist/describers",
    ("exploit", "^WATCHLIST_TECH"): EXPLOIT_API + "watchlist/technologies",
    ("exploit", "^STATS"): EXPLOIT_API + "stats",
    ("exploit", "^HEALTH"): EXPLOIT_API + "health",
}


def _is_static_query(mode: str, query: str) -> bool:
    return (mode, query) in STATIC_ENDPOINTS


BULK_MODES = ("bulk", "sbom")
ALL_MODES = tuple(MODES) + BULK_MODES + ("storekey",)


# --------------------------------------------------------------------------- #
# API key storage
# --------------------------------------------------------------------------- #

def _key_path() -> Path:
    return Path(os.path.expanduser("~")) / ".puncia"


async def store_key(key: str = "") -> None:
    """Persist an API key to ``~/.puncia`` with owner-only (0600) permissions."""
    path = _key_path()
    # Create with restrictive permissions from the outset rather than
    # writing world-readable and tightening afterwards.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(key.strip())
    try:  # O_CREAT's mode is ignored when the file already existed.
        os.chmod(str(path), 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass


async def read_key() -> str:
    """Return the API key from ``$PUNCIA_API_KEY`` or ``~/.puncia`` ("" if unset)."""
    env_key = os.environ.get("PUNCIA_API_KEY", "").strip()
    if env_key:
        return env_key
    try:
        return _key_path().read_text().strip()
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Request building (pure, and therefore easy to test)
# --------------------------------------------------------------------------- #

#: Longest keyword accepted for the `exploit` mode; a longer one is rejected
#: client-side with a clear error.
MAX_KEYWORD_LENGTH = 2048


def build_request(
    mode: str,
    query: str,
    match: str = "",
    scope: str = "",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    crawl: bool = False,
    filters: Optional[dict] = None,
) -> str:
    """Resolve a mode/query/match/scope/limit/offset/crawl/filters tuple into a full URL.

    ``scope`` narrows a keyword search to one domain (Subdomain Center's
    ammonites engine accepts ``keyword`` and ``domain`` together). ``limit``
    and ``offset`` page through an authenticated Subdomain Center result.
    ``crawl`` supplements a `subdomain` query with a live discovery pass. Of
    the Exploit Observer modes only `nuclei` pages (``limit``/``offset``) and
    takes ``filters``.

    Raises :class:`PunciaError` if the mode is unknown or the arguments are not
    valid for it. Kept free of I/O so the URL contract can be unit-tested —
    it has no notion of an API key, so it cannot enforce that `crawl` needs
    one; that check belongs to the caller (`query_api` does it).
    """
    spec = MODES.get(mode)
    if spec is None:
        known = ", ".join(sorted(MODES))
        raise PunciaError(f"unknown mode {mode!r} (expected one of: {known})")

    if (limit is not None or offset is not None) and spec.host != SUBDOMAIN_HOST and not spec.pageable:
        raise PunciaError(f"mode {mode!r} does not support pagination (--limit/--offset)")
    if filters:
        if not spec.filters:
            raise PunciaError(f"mode {mode!r} does not support --filter")
        unknown = sorted(set(filters) - set(spec.filters))
        if unknown:
            raise PunciaError(
                f"unknown filter(s) {', '.join(unknown)} for mode {mode!r} "
                f"(expected: {', '.join(spec.filters)})"
            )
    if spec.pageable and limit is not None and not 1 <= limit <= NUCLEI_MAX_PAGE:
        raise PunciaError(f"--limit for mode {mode!r} must be between 1 and {NUCLEI_MAX_PAGE}")
    # A page size of 0 would make every page look "full" to the walk.
    if limit is not None and limit < 1:
        raise PunciaError(f"--limit must be >= 1, got {limit}")
    if limit is not None and spec.host == SUBDOMAIN_HOST and limit > SUBDOMAIN_MAX_PAGE:
        raise PunciaError(
            f"--limit must be <= {SUBDOMAIN_MAX_PAGE} for mode {mode!r} "
            f"(Subdomain Center's absolute page-size bound), got {limit}"
        )
    if offset is not None and offset < 0:
        raise PunciaError(f"--offset must be >= 0, got {offset}")
    if offset is not None and offset > 0 and limit is None and not spec.pageable:
        raise PunciaError(
            "--offset > 0 requires --limit too: repeat the page size used on the earlier page"
        )
    if crawl and not spec.crawl_capable:
        raise PunciaError(f"mode {mode!r} does not support --crawl (only `subdomain` does)")
    if scope and not spec.scope_param:
        raise PunciaError(f"mode {mode!r} does not support --domain")

    # `query|match` is the legacy inline spelling of `--match`.
    query = query.strip()
    if "|" in query and spec.matches:
        query, _, inline_match = query.partition("|")
        query, inline_match = query.strip(), inline_match.strip()
        match = match or inline_match

    if _is_static_query(mode, query):
        return STATIC_ENDPOINTS[(mode, query)]

    if not query:
        raise PunciaError(f"mode {mode!r} requires a non-empty query")

    if mode == "exploit" and len(query) > MAX_KEYWORD_LENGTH:
        raise PunciaError(
            f"keyword is {len(query)} chars, over Exploit Observer's {MAX_KEYWORD_LENGTH}-char limit"
        )

    if match:
        if not spec.matches:
            raise PunciaError(f"mode {mode!r} does not support --match")
        if match not in spec.matches:
            allowed = ", ".join(spec.matches)
            raise PunciaError(
                f"invalid match {match!r} for mode {mode!r} (expected one of: {allowed})"
            )

    if spec.values:  # path-based endpoint, e.g. /noncve/{engine}
        if query not in spec.values:
            allowed = ", ".join(spec.values)
            raise PunciaError(
                f"invalid value {query!r} for mode {mode!r} (expected one of: {allowed})"
            )
        url = spec.url + quote(query, safe="")
        page_params: dict[str, str] = {k: str(v) for k, v in (filters or {}).items()}
        if limit is not None:
            page_params["limit"] = str(limit)
        if offset is not None:
            page_params["offset"] = str(offset)
        return url + ("?" + urlencode(page_params) if page_params else "")

    params: dict[str, str] = {}
    if spec.engine:
        params["engine"] = spec.engine
    params[spec.param] = query
    if scope:
        params[spec.scope_param] = scope
    if match:
        params["match"] = match
    if limit is not None:
        params["limit"] = str(limit)
    if offset is not None:
        params["offset"] = str(offset)
    if crawl:
        params["crawl"] = "true"
    return spec.url + "?" + urlencode(params)


# --------------------------------------------------------------------------- #
# Rate limiting & transport
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Spaces out requests so consecutive acquisitions are ``interval`` apart.

    A shared limiter is what actually enforces the free-tier budget: sleeping
    inside each task independently would let every task sleep concurrently and
    then fire at once.
    """

    def __init__(self, interval: float = 0.0) -> None:
        self.interval = interval
        self._next_at = 0.0

    async def acquire(self) -> None:
        """Reserve the next slot and wait for it.

        Deliberately lock-free: the reservation happens with no ``await`` in
        between, which is atomic on a single-threaded event loop. That keeps
        callers in arrival order and, unlike an ``asyncio.Lock``, leaves the
        limiter safe to construct outside of (or across) a running loop.
        """
        if self.interval <= 0:
            return
        now = time.monotonic()
        slot = max(now, self._next_at)
        self._next_at = slot + self.interval
        delay = slot - now
        if delay > 0:
            await asyncio.sleep(delay)


def make_limiters(apikey: str = "") -> dict[str, RateLimiter]:
    """Build per-host limiters; authenticated keys are not ratelimited."""
    if apikey:
        return {host: RateLimiter(0.0) for host in FREE_TIER_INTERVAL}
    return {host: RateLimiter(gap) for host, gap in FREE_TIER_INTERVAL.items()}


#: Process-wide limiters used by anonymous `query_api` calls that don't bring
#: their own, so consecutive calls from one process are paced together.
_DEFAULT_LIMITERS: dict[str, RateLimiter] = make_limiters("")


@asynccontextmanager
async def _session_scope(session: Optional[aiohttp.ClientSession], timeout: float):
    """Yield the caller's session untouched, or manage a short-lived one."""
    if session is not None:
        yield session
        return
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as owned:
        yield owned


def _extract_error_message(body_text: str) -> Optional[str]:
    """Pull the `error` field out of a `{"error": "..."}` body, if present."""
    try:
        parsed = json.loads(body_text)
    except (ValueError, TypeError):
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        return parsed["error"]
    return None


def _parse_retry_after(value: Optional[str], fallback: float) -> float:
    """Interpret a `Retry-After` header (seconds form only) or use ``fallback``."""
    if value is not None:
        try:
            seconds = float(value)
        except ValueError:
            pass
        else:
            if seconds >= 0:
                return seconds
    return fallback


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    limiter: Optional[RateLimiter],
    retries: int,
    timeout: float,
) -> tuple:
    """GET ``url`` and return ``(decoded_json, response_headers)``, retrying
    transient failures. ``response_headers`` is a case-insensitive mapping,
    so header lookups work whatever casing the response used, and is safe to
    use after the connection closes.

    ``timeout`` is applied per request, so it holds even when the caller
    supplied its own ``session`` built with a different (or no) timeout."""
    last_error: Optional[PunciaError] = None
    request_timeout = aiohttp.ClientTimeout(total=timeout)

    for attempt in range(retries + 1):
        if limiter is not None:
            await limiter.acquire()
        status: Optional[int] = None
        retry_after: Optional[str] = None
        try:
            async with session.get(url, headers=headers, timeout=request_timeout) as response:
                status = response.status
                if status == 200:
                    try:
                        data = await response.json(content_type=None)
                    except (ValueError, aiohttp.ContentTypeError) as exc:
                        raise PunciaError(f"malformed JSON in response: {exc}") from exc
                    return data, CIMultiDict(response.headers)
                retry_after = response.headers.get("Retry-After")
                body_text = (await response.text())[:500].strip()
        except asyncio.TimeoutError:
            last_error = PunciaError(f"request timed out after {timeout:g}s: {url}")
        except aiohttp.ClientError as exc:
            last_error = PunciaError(f"request failed ({type(exc).__name__}): {exc}")
        else:
            if status in (401, 403):
                raise PunciaError(
                    f"authentication failed (HTTP {status}) — check your key "
                    "via `puncia storekey <api-key>` or $PUNCIA_API_KEY"
                )
            if status == 404:
                raise PunciaError(f"not found (HTTP 404): {url}")
            message = _extract_error_message(body_text) or body_text[:200]
            last_error = PunciaError(f"HTTP {status}{': ' + message if message else ''}")
            # Only 429 and 5xx are worth another attempt.
            if status != 429 and not 500 <= status < 600:
                raise last_error

        if attempt < retries:
            delay = BACKOFF_BASE * (2 ** attempt)
            if status == 429:
                delay = _parse_retry_after(retry_after, delay)
            await asyncio.sleep(delay)

    raise last_error or PunciaError(f"request failed: {url}")


def _truthy_header(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


def _page_looks_full(rows: int, page_limit: Optional[int]) -> bool:
    """True when a page came back (nearly) as long as the page size requested.

    Such a page is walked past regardless of the truncation header; see
    :data:`PAGE_FULL_TOLERANCE`.
    """
    return page_limit is not None and rows >= page_limit * (1 - PAGE_FULL_TOLERANCE)


async def _fetch_all_pages(
    session: aiohttp.ClientSession,
    mode: str,
    query: str,
    match: str,
    scope: str,
    limit: Optional[int],
    headers: dict,
    limiter: Optional[RateLimiter],
    retries: int,
    timeout: float,
    on_page: Optional[Callable[[int, int], None]] = None,
    crawl: bool = False,
    on_crawl: Optional[Callable[[CIMultiDict], None]] = None,
) -> Any:
    """Walk every page of an authenticated Subdomain Center result and merge it.

    Continuation: ``X-Truncated: true`` always means another page follows.
    Otherwise the walk continues only past a page that came back (nearly) as
    long as the page size requested; a clearly short page, or an empty one,
    ends it (see :data:`PAGE_FULL_TOLERANCE`).

    The next offset is ``X-Next-Offset`` when present, else the current
    offset advanced by the rows served (the larger of the row count and
    ``X-Result-Count``) — never by the page size, so a walk can overlap but
    never skip. Rows are de-duplicated client-side, first-seen order kept,
    so an overlapping window cannot inflate the result.

    ``crawl`` is only sent on the first page. Every page carries an explicit
    ``limit``: the caller's, or :data:`SUBDOMAIN_DEFAULT_PAGE` when none was
    given, so the page size is the same on every request of the walk.
    """
    merged: list = []
    offset = 0
    page_limit = limit if limit is not None else SUBDOMAIN_DEFAULT_PAGE

    for page_number in range(1, MAX_PAGES + 1):
        page_crawl = crawl and page_number == 1
        url = build_request(mode, query, match, scope, limit=page_limit, offset=offset, crawl=page_crawl)
        data, resp_headers = await _fetch(session, url, headers, limiter, retries, timeout)
        if page_crawl and on_crawl is not None:
            on_crawl(resp_headers)

        if not isinstance(data, list):
            if page_number == 1:
                return data  # e.g. a validation-error payload — surface as-is
            raise PunciaError(
                f"page {page_number} returned a non-list response mid-walk "
                f"(offset={offset}); resume manually with --offset {offset} --limit {page_limit}"
            )

        merged.extend(data)
        if on_page is not None:
            on_page(page_number, len(merged))

        # "X-Truncated: true" is authoritative; otherwise only a (nearly) full
        # page is walked past, and an empty page always ends the walk.
        truncated_header = resp_headers.get("X-Truncated")
        has_more = bool(data) and (
            _truthy_header(truncated_header) or _page_looks_full(len(data), page_limit)
        )
        if not has_more:
            break

        next_offset = None
        next_offset_header = resp_headers.get("X-Next-Offset")
        if next_offset_header is not None:
            try:
                next_offset = int(next_offset_header)
            except ValueError:
                next_offset = None
        if next_offset is None:
            # No usable X-Next-Offset: advance by the rows served.
            try:
                result_count = int(resp_headers.get("X-Result-Count") or 0)
            except ValueError:
                result_count = 0
            next_offset = offset + max(len(data), result_count)

        if next_offset <= offset:  # guard against a non-advancing offset
            break
        offset = next_offset
    else:
        raise PunciaError(
            f"pagination did not complete within {MAX_PAGES} pages; "
            f"pass --offset {offset} --limit {page_limit} to continue manually"
        )

    # Overlapping windows can hand the same row back twice; collapse repeats,
    # keeping first-seen order.
    try:
        merged = list(dict.fromkeys(merged))
    except TypeError:  # unhashable rows (dict payloads) — leave as-is
        pass
    return merged


async def _fetch_all_candidates(
    session: aiohttp.ClientSession,
    mode: str,
    query: str,
    limit: Optional[int],
    filters: Optional[dict],
    headers: dict,
    limiter: Optional[RateLimiter],
    retries: int,
    timeout: float,
    on_page: Optional[Callable[[int, int], None]] = None,
) -> Any:
    """Walk every page of `nuclei candidates` and merge them into one
    ``{"generated", "total", "offset": 0, "limit", "candidates"}`` body.

    Continuation is read from the body's ``total``. A first page without a
    ``candidates`` list is returned as-is.
    """
    page_size = limit or NUCLEI_MAX_PAGE
    merged: list = []
    first: Optional[dict] = None
    offset = 0
    for page_number in range(1, MAX_PAGES + 1):
        url = build_request(mode, query, limit=page_size, offset=offset, filters=filters)
        data, _ = await _fetch(session, url, headers, limiter, retries, timeout)
        if not isinstance(data, dict) or "candidates" not in data:
            if page_number == 1:
                return data
            raise PunciaError(
                f"page {page_number} returned an unexpected body mid-walk "
                f"(offset={offset}); resume manually with --offset {offset}"
            )
        if first is None:
            first = data
        rows = data.get("candidates") or []
        merged.extend(rows)
        if on_page is not None:
            on_page(page_number, len(merged))
        offset += len(rows)
        if not rows or offset >= int(data.get("total") or 0):
            break
    else:
        raise PunciaError(
            f"pagination did not complete within {MAX_PAGES} pages; "
            f"pass --offset {offset} to continue manually"
        )
    return {**first, "offset": 0, "limit": len(merged), "candidates": merged}


#: Column order for `puncia nuclei candidates --format csv`. List fields are
#: joined with ";" (reasons with " | ", since a reason may contain ";").
#: ``protocol`` through ``xss_kind`` are the row's ``shape`` object flattened.
NUCLEI_CSV_COLUMNS = (
    "cve", "vedas_id", "priority", "feasibility", "impact", "recency_weight", "buildability",
    "protocol", "method", "authenticated", "likely_http", "surface", "state_change", "xss_kind",
    "product", "ecosystem", "platform", "cpe_missing", "cwe", "cvss",
    "vedas", "epss", "kev", "poc_strong", "poc_sources", "weak_sources",
    "portable_templates", "test_environments", "sibling_templates", "reasons",
)
#: A cell starting with one of these is evaluated as a formula by Excel /
#: Sheets / LibreOffice; each such cell is prefixed with "'" to keep it inert.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any, joiner: str = ";") -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        value = joiner.join(str(v) for v in value)
    text = str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


def candidates_to_csv(data: Any) -> str:
    """Render a `/nuclei/candidates` body (or just its ``candidates`` list)
    as CSV, one row per CVE in ranked order. ``{}`` (no key) gives a
    header-only CSV."""
    rows = data.get("candidates", []) if isinstance(data, dict) else (data or [])
    if not isinstance(rows, list):
        rows = []
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(NUCLEI_CSV_COLUMNS)
    for row in rows:
        if not isinstance(row, dict):
            continue
        shape = row.get("shape")
        # Flatten the shape object under the row; a row key wins on a clash.
        flat = {**(shape if isinstance(shape, dict) else {}), **row}
        writer.writerow(
            _csv_cell(flat.get(col), " | " if col == "reasons" else ";")
            for col in NUCLEI_CSV_COLUMNS
        )
    return buffer.getvalue()


async def write_csv(path, data: Any) -> None:
    """Write ``data`` as CSV to ``path`` (UTF-8; product names are not ASCII)."""
    try:
        async with aio_open(str(path), "w", newline="", encoding="utf-8") as handle:
            await handle.write(candidates_to_csv(data))
    except OSError as exc:
        raise PunciaError(f"cannot write {path}: {exc}") from exc


def emit_result(data: Any) -> str:
    """Print a result to stdout and return the exact JSON that was rendered.

    When stdout is not a terminal the payload is written raw, bypassing rich
    entirely: rich hard-wraps at the console width, which would split long
    values (hostnames, descriptions) across lines and emit invalid JSON to a
    pipe or file. Highlighting is only ever applied for human viewing.
    """
    payload = json.dumps(data, indent=4, sort_keys=True)
    if out_console.is_terminal and len(payload) <= RICH_JSON_MAX_BYTES:
        out_console.print(JSON(payload))
    else:
        sys.stdout.write(payload + "\n")
    return payload


async def write_json(path, data: Any) -> None:
    """Serialise ``data`` to ``path`` in the project's canonical JSON layout.

    Raises :class:`PunciaError` when the file cannot be written, so a bulk
    run records it as that job's failure instead of aborting every job.
    """
    try:
        async with aio_open(str(path), "w", encoding="utf-8") as handle:
            await handle.write(json.dumps(data, indent=4, sort_keys=True))
    except OSError as exc:
        raise PunciaError(f"cannot write {path}: {exc}") from exc


async def query_api(
    mode: str,
    query: str,
    output_file=None,
    *,
    apikey: str = "",
    match: str = "",
    scope: str = "",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    crawl: bool = False,
    filters: Optional[dict] = None,
    output_format: str = "json",
    on_headers: Optional[Callable[[CIMultiDict], None]] = None,
    on_page: Optional[Callable[[int, int], None]] = None,
    on_crawl: Optional[Callable[[CIMultiDict], None]] = None,
    session: Optional[aiohttp.ClientSession] = None,
    limiter: Optional[RateLimiter] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> Any:
    """Query one endpoint and return the decoded JSON.

    For an authenticated Subdomain Center query (``subdomain``/``replica``/
    ``keyword``) with no explicit ``offset``, every page of the result is
    walked and merged automatically. Pass ``offset`` to fetch exactly one
    page yourself instead; ``on_headers`` then receives that page's response
    headers (``X-Truncated``, ``X-Next-Offset``, ``X-Result-Count``) so you
    know whether and how to continue. ``offset > 0`` also requires ``limit``
    (repeat the page size the earlier page used). ``on_page`` is called after
    each page during an automatic walk as ``on_page(page_number, rows_so_far)``.

    ``crawl`` supplements a ``subdomain`` query with a live discovery pass
    (requires ``apikey``); ``on_crawl`` receives that request's response
    headers (``X-Crawl-Status``, ``X-Crawl-New-Count``).

    ``nuclei`` / ``candidates`` takes ``filters`` (keys from
    :data:`NUCLEI_FILTERS`) and, when authenticated with no ``offset``,
    walks every page into one body. ``output_format="csv"`` writes
    ``output_file`` as CSV (see :func:`candidates_to_csv`); the return value
    is always the decoded JSON.

    Static pseudo-queries (``^WATCHLIST_TECH``, ``^HEALTH``, ``^STATS``) skip
    both rate limiting and pagination regardless of ``apikey``.

    Raises :class:`PunciaError` on invalid input or an unrecoverable request
    failure. An empty result (``{}`` / ``[]``) is a legitimate answer and is
    returned, and written to ``output_file``, like any other.
    """
    query = query.strip()
    # Validate the whole argument set once, up front, whichever fetch path is
    # taken below: the page walkers rebuild URLs with only the arguments they
    # use, so without this a `match` or `scope` passed to `nuclei` (or a
    # `crawl` to `replica`) would be dropped silently instead of rejected.
    build_request(mode, query, match, scope, limit, offset, crawl, filters)
    spec = MODES[mode]
    if output_format not in ("json", "csv"):
        raise PunciaError(f"unknown output format {output_format!r} (expected json or csv)")
    if output_format == "csv" and mode != "nuclei":
        raise PunciaError("csv output is only supported for mode 'nuclei'")
    if crawl and not apikey:
        raise PunciaError("--crawl requires an API key")

    is_static = _is_static_query(mode, query)
    headers = {"X-API-Key": apikey} if apikey else {}
    if limiter is None and not apikey and not is_static:
        limiter = _DEFAULT_LIMITERS.get(spec.host)

    auto_paginate = (
        spec.host == SUBDOMAIN_HOST and bool(apikey) and offset is None and not is_static
    )
    walk_candidates = spec.pageable and bool(apikey) and offset is None

    async with _session_scope(session, timeout) as active:
        if walk_candidates:
            data = await _fetch_all_candidates(
                active, mode, query, limit, filters, headers, limiter, retries, timeout, on_page,
            )
        elif auto_paginate:
            data = await _fetch_all_pages(
                active, mode, query, match, scope, limit,
                headers, limiter, retries, timeout, on_page, crawl, on_crawl,
            )
        else:
            url = build_request(mode, query, match, scope, limit, offset, crawl, filters)
            data, resp_headers = await _fetch(active, url, headers, limiter, retries, timeout)
            if on_headers is not None:
                on_headers(resp_headers)
            if crawl and on_crawl is not None:
                on_crawl(resp_headers)

    if output_file is not None:
        if output_format == "csv":
            await write_csv(output_file, data)
        else:
            await write_json(output_file, data)
    return data


# --------------------------------------------------------------------------- #
# SBOM & bulk processing
# --------------------------------------------------------------------------- #

def sbom_process(sbom: dict) -> list:
    """Extract ``name@version`` fingerprints from a CycloneDX document.

    Anything that is not a JSON object (a bare list, a string) yields no
    fingerprints rather than an ``AttributeError``.
    """
    fingerprints: list = []
    if not isinstance(sbom, dict):
        return fingerprints

    def add_component(name, version) -> None:
        if isinstance(name, str) and isinstance(version, str) and name and version:
            fingerprints.append(f"{name}@{version}")

    metadata = sbom.get("metadata")
    metadata_component = (metadata.get("component") if isinstance(metadata, dict) else None) or {}
    if not isinstance(metadata_component, dict):
        metadata_component = {}
    add_component(metadata_component.get("name"), metadata_component.get("version"))
    for component in sbom.get("components") or []:
        if isinstance(component, dict):
            add_component(component.get("name"), component.get("version"))
    return fingerprints


def safe_output_path(
    root: Path, mode: str, query: str, disambiguate: bool = False
) -> Optional[Path]:
    """Resolve the output path for a (mode, query) pair, confined to ``root``.

    ``query`` routinely comes from third-party input — an SBOM authored by
    somebody else, a shared bulk target list — so path separators and control
    characters are scrubbed before the value is ever used as a filename, and
    the resolved path is re-checked against ``root`` regardless. Returns
    ``None`` when no safe path can be derived.

    A name that had to be altered (scrubbed, truncated, or a Windows device
    name) gets a short hash of the *original* query appended so two distinct
    queries that scrub to the same text (``a/b@1`` and ``a:b@1``) cannot
    silently overwrite each other's result; ``disambiguate`` forces the
    suffix for a name the caller already knows collides with another.
    """
    stem = UNSAFE_PATH_CHARS.sub("_", query).strip(". ")
    if not stem:
        return None
    altered = stem != query or bool(WINDOWS_RESERVED_NAMES.match(stem))
    if len(stem) > MAX_FILENAME_STEM:  # stay under NAME_MAX, keep it unique
        stem, altered = stem[:MAX_FILENAME_STEM], True
    if altered or disambiguate:
        digest = hashlib.sha256(query.encode("utf-8", "replace")).hexdigest()[:8]
        stem = f"{stem}~{digest}"

    destination = (root / mode / f"{stem}.json").resolve()
    try:
        destination.relative_to(root)
    except ValueError:
        return None
    return destination


def plan_bulk(input_file: dict, root: Path) -> tuple:
    """Turn a bulk/SBOM document into a de-duplicated list of jobs.

    Returns ``(jobs, warnings)`` where each job is ``(mode, query, destination)``.
    """
    jobs: list = []
    warnings: list = []
    seen: set = set()
    # Destinations already claimed, compared case-insensitively: macOS and
    # Windows filesystems would otherwise let `CVE-2021-1` and `cve-2021-1`
    # (distinct queries to the client) overwrite each other's file.
    taken: set = set()

    if not isinstance(input_file, dict):
        return [], ["input JSON must be an object mapping modes to query lists"]

    for mode, queries in input_file.items():
        if mode not in MODES:
            warnings.append(f"skipping unknown mode {mode!r}")
            continue
        if not isinstance(queries, list):
            warnings.append(f"skipping mode {mode!r}: expected a list of queries")
            continue
        for query in queries:
            if not isinstance(query, str) or not query.strip():
                warnings.append(f"skipping non-string query in mode {mode!r}")
                continue
            query = query.strip()
            if (mode, query) in seen:
                continue
            seen.add((mode, query))
            destination = safe_output_path(root, mode, query)
            if destination is not None and str(destination).lower() in taken:
                destination = safe_output_path(root, mode, query, disambiguate=True)
            if destination is None or str(destination).lower() in taken:
                warnings.append(f"skipping unsafe output path for {mode}/{query!r}")
                continue
            taken.add(str(destination).lower())
            jobs.append((mode, query, destination))
    return jobs, warnings


async def process_bulk(
    input_file: dict,
    output_directory,
    apikey: str = "",
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    limit: Optional[int] = None,
    crawl: bool = False,
    show_progress: bool = True,
) -> int:
    """Run every query in ``input_file``, writing results under ``output_directory``.

    Authenticated Subdomain Center jobs (``subdomain``/``replica``/``keyword``)
    are paginated automatically to completion, same as a single `query_api`
    call; ``limit`` optionally sets the page size used while walking. ``crawl``
    applies a live discovery pass to ``subdomain`` jobs only (the one mode
    that supports it); it's silently ignored for every other mode present.

    Returns the number of failed queries (0 meaning everything succeeded).
    Raises :class:`PunciaError` when the input yields no valid query at all —
    an input error, not a success with nothing to show for it.
    """
    root = Path(output_directory).resolve()
    jobs, warnings = plan_bulk(input_file, root)
    for warning in warnings:
        err_console.print(f"[yellow]warning:[/yellow] {escape(warning)}")
    if not jobs:
        raise PunciaError("nothing to do: no valid queries found in the input")

    for parent in {destination.parent for _, _, destination in jobs}:
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PunciaError(f"cannot create output directory {parent}: {exc}") from exc

    limiters = make_limiters(apikey)
    semaphore = asyncio.Semaphore(max(1, concurrency))
    failures: list = []

    progress = Progress(
        SpinnerColumn(style="bold green"),
        TextColumn("[bold cyan]puncia[/bold cyan]"),
        BarColumn(complete_style="green", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=err_console,
        disable=not show_progress,
    )

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        with progress:
            task_id = progress.add_task("querying", total=len(jobs))

            async def run_job(mode: str, query: str, destination: Path) -> None:
                async with semaphore:
                    try:
                        job_spec = MODES[mode]
                        static = _is_static_query(mode, query)
                        job_limit = limit if job_spec.host == SUBDOMAIN_HOST else None
                        job_crawl = crawl and job_spec.crawl_capable
                        await query_api(
                            mode,
                            query,
                            destination,
                            apikey=apikey,
                            limit=job_limit,
                            crawl=job_crawl,
                            session=session,
                            limiter=None if static else limiters.get(job_spec.host),
                            timeout=timeout,
                            retries=retries,
                        )
                    except PunciaError as exc:
                        failures.append((mode, query, str(exc)))
                    finally:
                        progress.advance(task_id)

            await asyncio.gather(*(run_job(m, q, d) for m, q, d in jobs))

    # `escape`: queries and messages are untrusted text and may contain
    # `[...]` that rich would otherwise parse as markup.
    for mode, query, message in failures:
        err_console.print(
            f"[bold red]failed:[/bold red] {escape(mode)}/{escape(query)} — {escape(message)}"
        )
    succeeded = len(jobs) - len(failures)
    err_console.print(
        f"[bold green]✓[/bold green] {succeeded}/{len(jobs)} queries written to "
        f"[bold]{escape(str(root))}[/bold]"
    )
    return len(failures)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

BANNER = (
    "[bold green]Panthera(P.)uncia[/bold green] [dim]v{version}[/dim]\n"
    "[cyan]subdomain recon · brand impersonation · exploit intel · sbom analysis — from the CLI[/cyan]\n"
    "[dim]A.R.P. Syndicate — https://www.arpsyndicate.io[/dim]"
)

EPILOG = """\
examples:
  puncia subdomain example.com              subdomains / shadow IT / takeover recon
  puncia replica example.com                lookalike & typosquat domains
  puncia keyword vpn --match prefix         hosts carrying a keyword
  puncia keyword vpn --domain example.com   the same, scoped to one domain
  puncia subdomain bandcamp.com --offset 0  one raw page (manual pagination)
  puncia subdomain example.com --crawl      supplement with a live crawl (needs a key)
  puncia exploit CVE-2021-44228             everything known about a CVE
  puncia exploit ^WATCHLIST_TECH            currently vulnerable technologies
  puncia exploit ^STATS                     aggregate vulnerability/exploit counts
  puncia noncve exploitable out.json        non-CVE VEDAS groups (needs a key)
  puncia nuclei candidates out.csv          CVEs worth a nuclei template, as CSV (needs a key)
  puncia nuclei candidates --filter platform=wordpress --filter poc=true
  puncia sbom bom.json ./results            scan a CycloneDX SBOM
  puncia bulk targets.json ./results        run a batch of queries

static pseudo-queries (unauthenticated, unlimited):
  puncia subdomain ^HEALTH          subdomain.center service health
  puncia exploit ^WATCHLIST_IDES    CVEs trending now + newly exploitable since the last crawl
  puncia exploit ^WATCHLIST_INFO    the same, with descriptions
  puncia exploit ^WATCHLIST_TECH    vulnerable technologies
  puncia exploit ^STATS             aggregate vulnerability/exploit counts
  puncia exploit ^HEALTH            exploit.observer service health

An API key lifts ratelimits: `puncia storekey <api-key>` or $PUNCIA_API_KEY.
Get one at https://www.arpsyndicate.io/pricing.html

pagination (mode `subdomain`/`replica`/`keyword`, requires an API key):
  With no --offset, every page is walked and merged automatically — an
  authenticated result has no total cap, so this is the "get everything"
  default. Pass --offset to fetch exactly one raw page yourself instead,
  e.g. for a resumable/streaming walk. Any --offset above 0 also needs
  --limit, repeating the page size an earlier page used.

nuclei candidates (mode `nuclei`, query `candidates`, requires an API key):
  CVEs with a VEDAS id and no nuclei template, highest priority first.
  Every page is fetched and merged unless --offset is given (--limit is
  the page size, at most 1000). Narrow with repeatable --filter KEY=VALUE:
  min_feasibility, vendor, product, platform, cwe, method (active, oast,
  version, fingerprint-first), protocol, kev, poc, portable. --format csv
  (or an output path ending in .csv) writes one row per CVE.

live crawl (mode `subdomain` only, requires an API key):
  --crawl supplements stored results with a live discovery pass. A given
  domain is only actually re-crawled once every ~6h; requests within that
  window get the cached crawl result instantly.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="puncia",
        description=(
            "Subdomain recon, brand-impersonation/shadow-IT discovery and exploit "
            "intelligence, powered by Subdomain Center and Exploit Observer."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"puncia {__version__}")
    parser.add_argument(
        "mode",
        choices=ALL_MODES,
        metavar="mode",
        help="one of: " + ", ".join(ALL_MODES),
    )
    parser.add_argument(
        "query",
        help="domain, keyword, identifier, engine, JSON file or API key (mode dependent)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="output file, or output directory for bulk/sbom modes",
    )
    parser.add_argument(
        "--match",
        metavar="MODE",
        default="",
        help="refine matching: exact, prefix or substring (mode dependent)",
    )
    parser.add_argument(
        "--domain",
        metavar="DOMAIN",
        default="",
        help="scope a keyword search to one domain (mode `keyword` only)",
    )
    parser.add_argument(
        "--filter",
        dest="filters",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="narrow `nuclei candidates` (repeatable), e.g. --filter kev=true",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("json", "csv"),
        default=None,
        help="output format; csv is `nuclei` only (default: json, or csv for a .csv output path)",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="supplement `subdomain` results with a live discovery pass (needs an API key)",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        metavar="N",
        help="page size for subdomain/replica/keyword (server default if omitted)",
    )
    parser.add_argument(
        "--offset",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help="fetch exactly one page starting here, instead of walking all pages",
    )
    parser.add_argument(
        "--api-key",
        default="",
        metavar="KEY",
        help="override the stored key and $PUNCIA_API_KEY for this run",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-request timeout (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--retries",
        type=_non_negative_int,
        default=DEFAULT_RETRIES,
        metavar="N",
        help=f"retries for timeouts, ratelimits and 5xx (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--concurrency",
        type=_positive_int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=f"parallel requests in bulk/sbom modes (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress output on stderr",
    )
    return parser


def _parse_filters(pairs: Sequence[str]) -> dict:
    filters: dict = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key or not value:
            raise PunciaError(f"--filter expects KEY=VALUE, got {pair!r}")
        if key in filters:
            raise PunciaError(f"--filter {key} given more than once")
        filters[key] = value
    return filters


def _non_negative_int(text: str) -> int:
    value = int(text)  # lets argparse's own int() raise on non-numeric input
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {value}")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if not value > 0:  # also rejects NaN
        raise argparse.ArgumentTypeError(f"must be > 0, got {text}")
    return value


def _load_json_document(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise PunciaError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PunciaError(f"{path} is not valid JSON: {exc}") from exc


async def run(argv: Optional[Sequence[str]] = None) -> int:
    """Execute one CLI invocation and return its exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv:
        err_console.print(Panel.fit(BANNER.format(version=__version__), border_style="green"))
        parser.print_help(sys.stderr)
        return 2

    args = parser.parse_args(argv)
    apikey = args.api_key.strip() or await read_key()

    if args.mode == "storekey":
        if not args.query.strip():
            raise PunciaError("storekey needs a non-empty API key")
        await store_key(args.query)
        err_console.print(
            f"[bold green]✓[/bold green] key stored in [bold]{escape(str(_key_path()))}[/bold] "
            "(mode 0600)"
        )
        return 0

    if args.mode in BULK_MODES:
        if not args.output:
            raise PunciaError(f"{args.mode} mode requires an output directory")
        # Per-query refinements have no place in a batch (each job runs with
        # its mode's defaults); say so rather than let them vanish silently.
        ignored = [
            flag for flag, given in (
                ("--match", args.match), ("--domain", args.domain), ("--filter", args.filters),
                ("--offset", args.offset is not None), ("--format", args.output_format),
            ) if given
        ]
        if ignored:
            err_console.print(
                f"[yellow]note:[/yellow] {', '.join(ignored)} do not apply to "
                f"{args.mode} mode and are ignored"
            )
        document = _load_json_document(args.query)
        if args.mode == "sbom":
            fingerprints = sbom_process(document)
            if not fingerprints:
                raise PunciaError(
                    f"no components with a name and version found in {args.query} "
                    "(expected a CycloneDX document)"
                )
            document = {"exploit": fingerprints}
        failures = await process_bulk(
            document,
            args.output,
            apikey,
            concurrency=args.concurrency,
            timeout=args.timeout,
            retries=args.retries,
            limit=args.limit,
            crawl=args.crawl,
            show_progress=not args.quiet,
        )
        return 1 if failures else 0

    spec = MODES[args.mode]
    query = args.query.strip()
    is_static = _is_static_query(args.mode, query)
    filters = _parse_filters(args.filters)
    output_format = args.output_format or (
        "csv" if args.output and str(args.output).lower().endswith(".csv") else "json")
    if output_format == "csv" and args.mode != "nuclei":
        raise PunciaError("--format csv is only supported for mode 'nuclei'")

    if spec.paid and not apikey and not is_static:
        err_console.print(
            f"[yellow]note:[/yellow] mode {args.mode!r} needs an API key; "
            "expect an empty result without one"
        )

    if (args.limit is not None or args.offset is not None) and not apikey and not is_static:
        err_console.print(
            "[yellow]note:[/yellow] --limit/--offset need an API key; the anonymous "
            "tier ignores them and always returns a shuffled sample of up to 500 rows"
        )

    if not apikey and not args.quiet and not is_static:
        interval = FREE_TIER_INTERVAL.get(spec.host, 0.0)
        if interval:
            err_console.print(
                f"[dim]no API key — pacing free-tier requests ~{interval:g}s apart[/dim]"
            )

    auto_paginating = (
        (spec.host == SUBDOMAIN_HOST or spec.pageable)
        and bool(apikey) and args.offset is None and not is_static
    )
    status = (
        err_console.status("[cyan]walking pages...[/cyan]", spinner="dots")
        if auto_paginating and not args.quiet
        else None
    )
    # CIMultiDict, not dict: headers arrive over HTTP/2 as e.g. `x-truncated`,
    # not `X-Truncated` — a plain dict would silently break every .get() below.
    page_hints: CIMultiDict = CIMultiDict()
    crawl_hints: CIMultiDict = CIMultiDict()

    def _on_page(page_number: int, rows_so_far: int) -> None:
        if status is not None:
            status.update(f"[cyan]walking pages...[/cyan] page {page_number}, {rows_so_far} rows so far")

    def _on_headers(resp_headers) -> None:
        page_hints.update(resp_headers)

    def _on_crawl(resp_headers) -> None:
        crawl_hints.update(resp_headers)

    if status is not None:
        status.start()
    try:
        result = await query_api(
            args.mode,
            query,
            args.output,
            apikey=apikey,
            match=args.match,
            scope=args.domain,
            limit=args.limit,
            offset=args.offset,
            crawl=args.crawl,
            filters=filters,
            output_format=output_format,
            on_headers=_on_headers,
            on_page=_on_page,
            on_crawl=_on_crawl,
            timeout=args.timeout,
            retries=args.retries,
        )
    finally:
        if status is not None:
            status.stop()

    if output_format == "csv":
        sys.stdout.write(candidates_to_csv(result))
    else:
        emit_result(result)
    if args.output:
        err_console.print(
            f"[bold green]✓[/bold green] written to [bold]{escape(str(args.output))}[/bold]"
        )
    if crawl_hints:
        crawl_status = crawl_hints.get("X-Crawl-Status", "unknown")
        new_count = crawl_hints.get("X-Crawl-New-Count", "0")
        err_console.print(
            f"[dim]crawl: {escape(crawl_status)}, {escape(new_count)} newly discovered name(s)[/dim]"
        )
        # Only the aggregate status and count are shown; no other crawl
        # header is echoed.
        if crawl_status in ("partial", "running"):
            err_console.print(
                "[dim]crawl: more results still coming — re-run with --crawl in a minute[/dim]"
            )
    if args.offset is not None and not is_static:
        _print_continuation_hint(spec, args, result, page_hints)
    return 0


def _print_continuation_hint(spec: Mode, args: argparse.Namespace, result: Any,
                             page_hints: CIMultiDict) -> None:
    """After a manual (``--offset``) page, tell the user how to fetch the next one.

    Subdomain Center continuation is read from the response headers
    (``X-Truncated``, ``X-Next-Offset``, ``X-Result-Count``); `nuclei
    candidates` continuation from the body (``total``/``offset``/
    ``candidates``). The two are never mixed.
    """
    if spec.pageable:
        if not isinstance(result, dict) or not isinstance(result.get("candidates"), list):
            return
        try:
            total = int(result.get("total") or 0)
            page_offset = int(result.get("offset") or (args.offset or 0))
        except (TypeError, ValueError):
            return
        next_offset = page_offset + len(result["candidates"])
        if result["candidates"] and next_offset < total:
            limit_hint = f" --limit {args.limit}" if args.limit is not None else ""
            err_console.print(
                f"[yellow]note:[/yellow] {next_offset} of {total} candidates seen — "
                f"continue with --offset {next_offset}{limit_hint}"
            )
        return

    if spec.host != SUBDOMAIN_HOST:
        return
    truncated = _truthy_header(page_hints.get("X-Truncated"))
    seen = page_hints.get("X-Result-Count")
    rows_in_body = len(result) if isinstance(result, list) else 0
    try:
        seen_rows = int(seen) if seen is not None else rows_in_body
    except ValueError:
        seen_rows = rows_in_body
    # A (nearly) full page is treated as "more may follow" whatever the
    # truncation header says (see PAGE_FULL_TOLERANCE).
    looks_full = seen_rows > 0 and _page_looks_full(seen_rows, args.limit)
    if not (truncated or looks_full):
        return
    next_offset: Any = page_hints.get("X-Next-Offset")
    if next_offset is None:
        # Step by the rows served, never by the page size: overlap, not a gap.
        next_offset = (args.offset or 0) + seen_rows if seen_rows else "?"
    # offset>0 requires limit= too; a page fetched without --limit used the
    # default page size, so that is the size to repeat.
    effective_limit = args.limit if args.limit is not None else SUBDOMAIN_DEFAULT_PAGE
    what = (
        "more results available"
        if truncated
        else "page came back full-sized, more results may exist"
    )
    err_console.print(
        f"[yellow]note:[/yellow] {what} — continue with --offset {escape(str(next_offset))} "
        f"--limit {effective_limit}"
    )


async def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return await run(argv)
    except PunciaError as exc:
        # Error text may contain untrusted input; escape it so a
        # `[`-containing value is printed, not parsed as rich markup.
        err_console.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        return 1
    except KeyboardInterrupt:  # pragma: no cover - interactive
        err_console.print("[yellow]interrupted[/yellow]")
        return 130


def scriptrun() -> None:
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        sys.exit(130)


if __name__ == "__main__":
    scriptrun()
