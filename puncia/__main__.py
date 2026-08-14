"""Panthera(P.)uncia — subdomain recon, brand-impersonation & exploit intelligence CLI.

Thin, well-behaved client for two A.R.P. Syndicate APIs:

* Subdomain Center  — subdomain enumeration, shadow IT, lookalike/typosquat domains
* Exploit Observer  — vulnerability & exploit intelligence, CVE/GHSA enrichment, SBOM scanning
"""

from __future__ import annotations

import argparse
import asyncio
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
from rich.console import Console
from rich.json import JSON
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

#: Minimum seconds between unauthenticated requests, per host. Authenticated
#: keys have no ratelimit, so these are only applied when no key is present.
#: exploit.observer allows 2 requests/minute per IP; 31s leaves a safety margin.
FREE_TIER_INTERVAL = {SUBDOMAIN_HOST: 5.0, EXPLOIT_HOST: 31.0}

DEFAULT_TIMEOUT = 60.0
DEFAULT_RETRIES = 2
DEFAULT_CONCURRENCY = 10
BACKOFF_BASE = 2.0

#: Hard ceiling on pages walked for one query, purely so a server that never
#: reports "X-Truncated: false" (or an offset that stops advancing) can't
#: hang the CLI forever. High enough to be a non-issue for any real dataset.
MAX_PAGES = 10_000

#: Characters that could escape a path segment. Any query that becomes a
#: filename (SBOM component names, bulk input) is scrubbed of these first.
UNSAFE_PATH_CHARS = re.compile(r"[\\/:\x00-\x1f\x7f]")
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
    extra: tuple = ()  # additional fixed query parameters
    matches: tuple = ()  # permitted `match` values ( () == unsupported )
    values: tuple = ()  # permitted values for path-based modes
    scope_param: str = ""  # optional secondary param narrowing the search
    paid: bool = False
    help: str = ""


MODES: dict[str, Mode] = {
    "subdomain": Mode(
        SUBDOMAIN_API,
        SUBDOMAIN_HOST,
        param="domain",
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
    "enrich": Mode(
        EXPLOIT_API,
        EXPLOIT_HOST,
        param="keyword",
        extra=(("enrich", "True"),),
        matches=("substring", "prefix", "exact"),
        help="as `exploit`, plus EPSS/VEDAS scores and correlated references",
    ),
    "noncve": Mode(
        EXPLOIT_API + "noncve/",
        EXPLOIT_HOST,
        values=("browser", "china", "russia", "europe", "exploitable"),
        paid=True,
        help="non-CVE identifiers clustered by VEDAS group (requires an API key)",
    ),
}

#: Pseudo-queries under `exploit` that map to the unauthenticated watchlists.
WATCHLISTS = {
    "^WATCHLIST_IDES": "watchlist/identifiers",
    "^WATCHLIST_INFO": "watchlist/describers",
    "^WATCHLIST_TECH": "watchlist/technologies",
}

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

def build_request(
    mode: str,
    query: str,
    match: str = "",
    scope: str = "",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> str:
    """Resolve a mode/query/match/scope/limit/offset tuple into a full URL.

    ``scope`` narrows a keyword search to one domain (Subdomain Center's
    ammonites engine accepts ``keyword`` and ``domain`` together). ``limit``
    and ``offset`` page through an authenticated Subdomain Center result;
    they are not meaningful for Exploit Observer endpoints.

    Raises :class:`PunciaError` if the mode is unknown or the arguments are not
    valid for it. Kept free of I/O so the URL contract can be unit-tested.
    """
    spec = MODES.get(mode)
    if spec is None:
        known = ", ".join(sorted(MODES))
        raise PunciaError(f"unknown mode {mode!r} (expected one of: {known})")

    if (limit is not None or offset is not None) and spec.host != SUBDOMAIN_HOST:
        raise PunciaError(f"mode {mode!r} does not support pagination (--limit/--offset)")
    if limit is not None and limit < 0:
        raise PunciaError(f"--limit must be >= 0, got {limit}")
    if offset is not None and offset < 0:
        raise PunciaError(f"--offset must be >= 0, got {offset}")

    # `query|match` is the legacy inline spelling of `--match`.
    if "|" in query and spec.matches:
        query, _, inline_match = query.partition("|")
        match = match or inline_match

    if mode == "exploit" and query in WATCHLISTS:
        return spec.url + WATCHLISTS[query]

    query = query.strip()
    if not query:
        raise PunciaError(f"mode {mode!r} requires a non-empty query")

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
        return spec.url + quote(query, safe="")

    if scope and not spec.scope_param:
        raise PunciaError(f"mode {mode!r} does not support --domain")

    params: dict[str, str] = dict(spec.extra)
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


@asynccontextmanager
async def _session_scope(session: Optional[aiohttp.ClientSession], timeout: float):
    """Yield the caller's session untouched, or manage a short-lived one."""
    if session is not None:
        yield session
        return
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as owned:
        yield owned


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    limiter: Optional[RateLimiter],
    retries: int,
    timeout: float,
) -> tuple:
    """GET ``url`` and return ``(decoded_json, response_headers)``, retrying
    transient failures. ``response_headers`` is a plain dict, safe to use
    after the connection closes."""
    last_error: Optional[PunciaError] = None

    for attempt in range(retries + 1):
        if limiter is not None:
            await limiter.acquire()
        try:
            async with session.get(url, headers=headers) as response:
                status = response.status
                if status == 200:
                    try:
                        data = await response.json(content_type=None)
                    except (ValueError, aiohttp.ContentTypeError) as exc:
                        raise PunciaError(f"malformed JSON in response: {exc}") from exc
                    return data, dict(response.headers)
                snippet = (await response.text())[:200].strip()
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
            last_error = PunciaError(f"HTTP {status}{': ' + snippet if snippet else ''}")
            # Only ratelimits and server faults are worth another attempt.
            if status != 429 and not 500 <= status < 600:
                raise last_error

        if attempt < retries:
            await asyncio.sleep(BACKOFF_BASE * (2 ** attempt))

    raise last_error or PunciaError(f"request failed: {url}")


def _truthy_header(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


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
) -> Any:
    """Walk every page of an authenticated Subdomain Center result and merge it.

    Continuation is driven *only* by an explicit ``X-Truncated: true`` on the
    response — never inferred from row counts. The pagination contract is
    being rolled out server-side incrementally, so today's responses may
    carry ``X-Result-Count`` without ``X-Truncated``/``X-Next-Offset`` yet (or
    report ``X-Truncated: false`` unconditionally); either way, treating "no
    explicit continue signal" as "this is everything" means this function is
    a correct single-page fetch today and starts walking automatically the
    moment the server finishes shipping the feature — no client change needed.
    """
    merged: list = []
    offset = 0

    for page_number in range(1, MAX_PAGES + 1):
        url = build_request(mode, query, match, scope, limit=limit, offset=offset)
        data, resp_headers = await _fetch(session, url, headers, limiter, retries, timeout)

        if not isinstance(data, list):
            if page_number == 1:
                return data  # e.g. a validation-error payload — surface as-is
            raise PunciaError(
                f"page {page_number} returned a non-list response mid-walk "
                f"(offset={offset}); resume manually with --offset {offset}"
            )

        merged.extend(data)
        if on_page is not None:
            on_page(page_number, len(merged))

        truncated_header = resp_headers.get("X-Truncated")
        if truncated_header is None or not _truthy_header(truncated_header) or not data:
            break

        next_offset_header = resp_headers.get("X-Next-Offset")
        if next_offset_header is not None:
            try:
                next_offset = int(next_offset_header)
            except ValueError:
                next_offset = offset + len(data)
        else:
            result_count = resp_headers.get("X-Result-Count")
            try:
                next_offset = offset + (int(result_count) if result_count is not None else len(data))
            except ValueError:
                next_offset = offset + len(data)

        if next_offset <= offset:  # guard against a non-advancing/misbehaving server
            break
        offset = next_offset
    else:
        raise PunciaError(
            f"pagination did not complete within {MAX_PAGES} pages; "
            f"pass --offset to continue manually from offset={offset}"
        )

    return merged


def emit_result(data: Any) -> str:
    """Print a result to stdout and return the exact JSON that was rendered.

    When stdout is not a terminal the payload is written raw, bypassing rich
    entirely: rich hard-wraps at the console width, which would split long
    values (hostnames, descriptions) across lines and emit invalid JSON to a
    pipe or file. Highlighting is only ever applied for human viewing.
    """
    payload = json.dumps(data, indent=4, sort_keys=True)
    if out_console.is_terminal:
        out_console.print(JSON(payload))
    else:
        sys.stdout.write(payload + "\n")
    return payload


async def write_json(path, data: Any) -> None:
    """Serialise ``data`` to ``path`` in the project's canonical JSON layout."""
    async with aio_open(str(path), "w") as handle:
        await handle.write(json.dumps(data, indent=4, sort_keys=True))


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
    on_headers: Optional[Callable[[dict], None]] = None,
    on_page: Optional[Callable[[int, int], None]] = None,
    session: Optional[aiohttp.ClientSession] = None,
    limiter: Optional[RateLimiter] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> Any:
    """Query one endpoint and return the decoded JSON.

    For an authenticated Subdomain Center query (``subdomain``/``replica``/
    ``keyword``) with no explicit ``offset``, every page of the result is
    walked and merged automatically — matching the API's "no total cap for
    authenticated results" contract. Pass ``offset`` (with or without
    ``limit``) to fetch exactly one page yourself instead; ``on_headers`` then
    receives that page's response headers (``X-Truncated``, ``X-Next-Offset``,
    ``X-Result-Count``) so you know whether and how to continue. ``on_page``
    is called after each page during an automatic walk as
    ``on_page(page_number, rows_so_far)``.

    Raises :class:`PunciaError` on invalid input or an unrecoverable request
    failure. An empty result (``{}`` / ``[]``) is a legitimate answer and is
    returned, and written to ``output_file``, like any other.
    """
    spec = MODES.get(mode)
    if spec is None:
        build_request(mode, query, match, scope, limit, offset)  # raises with a clear message

    headers = {"X-API-Key": apikey} if apikey else {}
    if limiter is None and not apikey:
        limiter = RateLimiter(FREE_TIER_INTERVAL.get(spec.host, 0.0))

    auto_paginate = spec.host == SUBDOMAIN_HOST and bool(apikey) and offset is None

    async with _session_scope(session, timeout) as active:
        if auto_paginate:
            data = await _fetch_all_pages(
                active, mode, query, match, scope, limit,
                headers, limiter, retries, timeout, on_page,
            )
        else:
            url = build_request(mode, query, match, scope, limit, offset)
            data, resp_headers = await _fetch(active, url, headers, limiter, retries, timeout)
            if on_headers is not None:
                on_headers(resp_headers)

    if output_file is not None:
        await write_json(output_file, data)
    return data


# --------------------------------------------------------------------------- #
# SBOM & bulk processing
# --------------------------------------------------------------------------- #

def sbom_process(sbom: dict) -> list:
    """Extract ``name@version`` fingerprints from a CycloneDX document."""
    fingerprints: list = []

    def add_component(name, version) -> None:
        if isinstance(name, str) and isinstance(version, str) and name and version:
            fingerprints.append(f"{name}@{version}")

    metadata_component = (sbom.get("metadata") or {}).get("component") or {}
    add_component(metadata_component.get("name"), metadata_component.get("version"))
    for component in sbom.get("components") or []:
        if isinstance(component, dict):
            add_component(component.get("name"), component.get("version"))
    return fingerprints


def safe_output_path(root: Path, mode: str, query: str) -> Optional[Path]:
    """Resolve the output path for a (mode, query) pair, confined to ``root``.

    ``query`` routinely comes from third-party input — an SBOM authored by
    somebody else, a shared bulk target list — so path separators and control
    characters are scrubbed before the value is ever used as a filename, and
    the resolved path is re-checked against ``root`` regardless. Returns
    ``None`` when no safe path can be derived.
    """
    stem = UNSAFE_PATH_CHARS.sub("_", query).strip(". ")
    if not stem:
        return None
    if len(stem) > MAX_FILENAME_STEM:  # stay under NAME_MAX, keep it unique
        digest = hashlib.sha256(query.encode("utf-8", "replace")).hexdigest()[:8]
        stem = f"{stem[:MAX_FILENAME_STEM]}~{digest}"

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
            if (mode, query) in seen:
                continue
            seen.add((mode, query))
            destination = safe_output_path(root, mode, query)
            if destination is None:
                warnings.append(f"skipping unsafe output path for {mode}/{query!r}")
                continue
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
    show_progress: bool = True,
) -> int:
    """Run every query in ``input_file``, writing results under ``output_directory``.

    Authenticated Subdomain Center jobs (``subdomain``/``replica``/``keyword``)
    are paginated automatically to completion, same as a single `query_api`
    call; ``limit`` optionally sets the page size used while walking.

    Returns the number of failed queries (0 meaning everything succeeded).
    """
    root = Path(output_directory).resolve()
    jobs, warnings = plan_bulk(input_file, root)
    for warning in warnings:
        err_console.print(f"[yellow]warning:[/yellow] {warning}")
    if not jobs:
        err_console.print("[bold red]nothing to do:[/bold red] no valid queries found")
        return 0

    for _, _, destination in jobs:
        destination.parent.mkdir(parents=True, exist_ok=True)

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
                        job_limit = limit if MODES[mode].host == SUBDOMAIN_HOST else None
                        await query_api(
                            mode,
                            query,
                            destination,
                            apikey=apikey,
                            limit=job_limit,
                            session=session,
                            limiter=limiters.get(MODES[mode].host),
                            timeout=timeout,
                            retries=retries,
                        )
                    except PunciaError as exc:
                        failures.append((mode, query, str(exc)))
                    finally:
                        progress.advance(task_id)

            await asyncio.gather(*(run_job(m, q, d) for m, q, d in jobs))

    for mode, query, message in failures:
        err_console.print(f"[bold red]failed:[/bold red] {mode}/{query} — {message}")
    succeeded = len(jobs) - len(failures)
    err_console.print(
        f"[bold green]✓[/bold green] {succeeded}/{len(jobs)} queries written to [bold]{root}[/bold]"
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
  puncia exploit CVE-2021-44228             everything known about a CVE
  puncia enrich GHSA-jfh8-c2jp-5v3q         the same, plus EPSS/VEDAS scoring
  puncia exploit ^WATCHLIST_TECH            currently vulnerable technologies
  puncia noncve exploitable out.json        non-CVE VEDAS groups (needs a key)
  puncia sbom bom.json ./results            scan a CycloneDX SBOM
  puncia bulk targets.json ./results        run a batch of queries

watchlist pseudo-queries (mode `exploit`, no key required):
  ^WATCHLIST_IDES   vulnerability & exploit identifiers
  ^WATCHLIST_INFO   the same, with descriptions
  ^WATCHLIST_TECH   vulnerable technologies

An API key lifts ratelimits: `puncia storekey <api-key>` or $PUNCIA_API_KEY.
Get one at https://www.arpsyndicate.io/pricing.html

pagination (mode `subdomain`/`replica`/`keyword`, requires an API key):
  With no --offset, every page is walked and merged automatically — an
  authenticated result has no total cap, so this is the "get everything"
  default. Pass --offset (with or without --limit) to fetch exactly one
  raw page yourself instead, e.g. for a resumable/streaming walk.
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
        "--limit",
        type=_non_negative_int,
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
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-request timeout (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        metavar="N",
        help=f"retries for timeouts, ratelimits and 5xx (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
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


def _non_negative_int(text: str) -> int:
    value = int(text)  # lets argparse's own int() raise on non-numeric input
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
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
        await store_key(args.query)
        err_console.print(
            f"[bold green]✓[/bold green] key stored in [bold]{_key_path()}[/bold] (mode 0600)"
        )
        return 0

    if args.mode in BULK_MODES:
        if not args.output:
            raise PunciaError(f"{args.mode} mode requires an output directory")
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
            show_progress=not args.quiet,
        )
        return 1 if failures else 0

    spec = MODES[args.mode]

    if spec.paid and not apikey:
        err_console.print(
            f"[yellow]note:[/yellow] mode {args.mode!r} needs an API key; "
            "expect an empty result without one"
        )

    if (args.limit is not None or args.offset is not None) and not apikey:
        err_console.print(
            "[yellow]note:[/yellow] --limit/--offset need an API key; the anonymous "
            "tier ignores them and always returns a shuffled sample of up to 500 rows"
        )

    if not apikey and not args.quiet:
        interval = FREE_TIER_INTERVAL.get(spec.host, 0.0)
        if interval:
            err_console.print(
                f"[dim]no API key — pacing free-tier requests ~{interval:g}s apart[/dim]"
            )

    auto_paginating = spec.host == SUBDOMAIN_HOST and bool(apikey) and args.offset is None
    status = (
        err_console.status("[cyan]walking pages...[/cyan]", spinner="dots")
        if auto_paginating and not args.quiet
        else None
    )
    page_hints: dict = {}

    def _on_page(page_number: int, rows_so_far: int) -> None:
        if status is not None:
            status.update(f"[cyan]walking pages...[/cyan] page {page_number}, {rows_so_far} rows so far")

    def _on_headers(resp_headers: dict) -> None:
        page_hints.update(resp_headers)

    if status is not None:
        status.start()
    try:
        result = await query_api(
            args.mode,
            args.query,
            args.output,
            apikey=apikey,
            match=args.match,
            scope=args.domain,
            limit=args.limit,
            offset=args.offset,
            on_headers=_on_headers,
            on_page=_on_page,
            timeout=args.timeout,
            retries=args.retries,
        )
    finally:
        if status is not None:
            status.stop()

    emit_result(result)
    if args.output:
        err_console.print(f"[bold green]✓[/bold green] written to [bold]{args.output}[/bold]")
    if _truthy_header(page_hints.get("X-Truncated")):
        next_offset = page_hints.get("X-Next-Offset")
        if next_offset is None:
            seen = page_hints.get("X-Result-Count")
            next_offset = (args.offset or 0) + int(seen) if seen is not None else "?"
        err_console.print(
            f"[yellow]note:[/yellow] more results available — continue with --offset {next_offset}"
        )
    return 0


async def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return await run(argv)
    except PunciaError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
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
