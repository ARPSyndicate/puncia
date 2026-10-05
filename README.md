# Panthera(P.)uncia

### Official CLI utility for Subdomain Center & Exploit Observer

[![Downloads](https://pepy.tech/badge/puncia)](https://pepy.tech/project/puncia)
<img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
<img alt="GitHub stars" src="https://img.shields.io/github/stars/ARPSyndicate/puncia">
<br>
<img src="https://raw.githubusercontent.com/ARPSyndicate/puncia/master/puncia.png" width=25%>
<br>

**Puncia** is the official command-line client for two A.R.P. Syndicate intelligence APIs — point it at a domain, a brand, or a vulnerability ID and get structured JSON back in seconds, no browser required:

- 🕸️ **[Subdomain Center](https://subdomain.center)** — subdomain enumeration, **subdomain takeover** surfacing, **shadow IT discovery**, and **brand impersonation / lookalike-domain (typosquat) detection** at internet scale.
- 💥 **[Exploit Observer](https://exploit.observer)** — exploit & vulnerability intelligence across 150+ identifier schemes (CVE, GHSA, EDB, MSF, ZDI, nation-state feeds and more), with CVE/GHSA enrichment (EPSS + VEDAS maturity scoring) and SBOM scanning.

```text
$ puncia subdomain arpsyndicate.io
╭──────────────────────────────────────────────────────────────────────╮
│ Panthera(P.)uncia v0.40                                              │
│ subdomain recon · brand impersonation · exploit intel · sbom analysis│
│ A.R.P. Syndicate — https://www.arpsyndicate.io                       │
╰──────────────────────────────────────────────────────────────────────╯
[
  "advisories.arpsyndicate.io",
  "asm.arpsyndicate.io",
  "blog.arpsyndicate.io",
  ...
]

$ puncia sbom bom.json ./out
puncia ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (128/128) 0:00:41
```

**Please note that although these results can sometimes be pretty inaccurate & unreliable, they can greatly differ from time to time due to their self-improvement capabilities.**

**Aggressive rate-limits can be avoided with an API key: https://www.arpsyndicate.io/pricing.html**

## Practical Applications

1. **Brand Impersonation & Phishing Domain Detection**  
   Surface replica, lookalike, and typosquat domains riding on your brand before they're used against you or your customers.
2. **Shadow IT & External Attack Surface Discovery**  
   Identify and monitor exposed subdomains and infrastructure spun up outside official channels.
3. **Subdomain Takeover Reconnaissance**  
   Enumerate the full subdomain footprint of a target, a key first step in spotting dangling/takeover-prone records.
4. **Advanced Vulnerability Research & Monitoring**  
   Discover and track known and emerging threats, including obscure or unlisted vulnerabilities.
5. **Contextual Enrichment of CVE/GHSA Data**  
   Add depth and actionable intelligence (EPSS + VEDAS maturity scores) to known vulnerabilities for better prioritization.
6. **Vulnerability Detection in Software Bill of Materials (SBOM)**  
   Analyze software components for known exploits and security issues using structured SBOM data.
7. **Seamless Integration with CI/CD & Threat Intel Workflows**  
   Automate intelligence gathering and vulnerability checks within development or security pipelines.
8. **Monitoring Nation-State Exploit Trends**  
   Stay ahead of threats by tracking vulnerabilities flagged by foreign actors but not yet recognized by mainstream databases.
9. **Keyword-Based Subdomain Discovery**  
   Surface hosts carrying a given keyword across the internet, independent of a specific parent domain.
10. **Bulk Threat Intelligence Processing**  
   Run batch queries (domains, vulnerabilities, etc.) for scalable analysis across large datasets or enterprise asset inventories.
11. **Passive Reconnaissance for Red Teams**  
   Conduct stealthy reconnaissance by using passive data sources (no direct interaction with targets).
12. **Open Source Intelligence (OSINT) Collection**  
   Combine subdomain and exploit intelligence to enhance OSINT investigations.
13. **Compliance & Risk Management Support**  
   Enrich vulnerability data to support compliance audits (e.g., ISO 27001, SOC 2) with deeper context.


## Installation

1. From PyPi - `pip3 install puncia`
2. From Source - `pip3 install .`<br>

### 30-second Quickstart

```bash
pip3 install puncia

# subdomain footprint of a target (shadow IT / attack surface / takeover recon)
puncia subdomain example.com

# lookalike / typosquat / brand-impersonation domains
puncia replica example.com

# what's known about a CVE
puncia exploit CVE-2021-44228
```


## Usage

```
puncia <mode> <query> [output] [--match M] [--domain D] [--limit N] [--offset N]
                               [--crawl] [--filter KEY=VALUE] [--format json|csv]
                               [--api-key K] [--concurrency N]
                               [--timeout S] [--retries N] [--quiet]
```

Run `puncia --help` for the full reference. Results are printed to **stdout**; the
banner, progress bars, warnings and errors all go to **stderr**, so
`puncia subdomain example.com > out.json` always yields clean, valid JSON.

**Exit codes:** `0` success · `1` request or input error · `2` usage error.

1.  (PAID) Store an API key (storekey) - `puncia storekey <api-key>`
    - Stored at `~/.puncia` with `0600` permissions. `$PUNCIA_API_KEY` overrides it,
      which is usually what you want in CI.
2.  (FREEMIUM) Query Domains, clustered by domain (subdomain / `cuttlefish` engine) - `puncia subdomain <domain> <output-file>`
    - **Pagination (authenticated only):** an authenticated result has no total
      cap. By default `subdomain`/`replica`/`keyword` walk every page and merge
      them for you. Pass `--offset` (with or without `--limit`) to fetch exactly
      one raw page yourself instead, e.g. for a resumable or streaming walk:
      ```bash
      puncia subdomain bigco.com --limit 50000 --offset 0
      # stderr prints: note: more results available — continue with --offset 50000
      puncia subdomain bigco.com --limit 50000 --offset 50000
      ```
      Anonymous requests ignore `--limit`/`--offset` server-side (always a
      shuffled sample of up to 500 rows); puncia warns rather than pretending
      they did something.
    - **Live crawl (authenticated only):** `--crawl` supplements stored results
      with a live discovery pass. A given domain is only actually re-crawled
      once every ~6h — requests inside that window get the cached crawl result
      instantly. Puncia reports the outcome on stderr:
      `crawl: fresh, 12 newly discovered name(s)` (also `partial` / `running` /
      `cooldown` / `disabled`). On `partial`/`running` part of the crawl is
      still going server-side; re-run with `--crawl` in a minute for the rest.
      ```bash
      puncia subdomain bigco.com --crawl
      ```
3.  (FREEMIUM) Query Replica Domains, clustered by brand (replica / `octopus` engine) - `puncia replica <domain> --match <prefix|exact|substring> <output-file>`
4.  (FREEMIUM) Query by Keyword, clustered by keyword (keyword / `ammonites` engine) - `puncia keyword <keyword> --match <exact|prefix> <output-file>`
    - Optionally scope the keyword to a single domain with `--domain`:
      `puncia keyword blog --domain bandcamp.com`
5.  Query Exploit & Vulnerability Identifiers (exploit)
    - (FREE) Watchlist (^WATCHLIST_IDES) — CVEs **trending** in the latest crawl plus CVEs that became **exploitable for the first time** in it; rebuilt every crawl - `puncia exploit ^WATCHLIST_IDES  <output-file>`
    - (FREE) Vulnerability & Exploit Identifers Watchlist with Descriptions (^WATCHLIST_INFO) - `puncia exploit ^WATCHLIST_INFO  <output-file>`
    - (FREE) Vulnerable Technologies Watchlist (^WATCHLIST_TECH) - `puncia exploit ^WATCHLIST_TECH  <output-file>`
    - (FREE) Aggregate vulnerability/exploit stats (^STATS) - `puncia exploit ^STATS  <output-file>`
    - (FREE) Service health (^HEALTH) - `puncia exploit ^HEALTH  <output-file>`
    - (FREEMIUM) [Supported Vulnerability Identifiers](https://github.com/ARPSyndicate/docs?tab=readme-ov-file#supported-vulnerability-identifiers) - `puncia exploit <eoidentifier> --match <substring|prefix|exact> <output-file>`
    - Metasploit modules come back as their Rapid7 module page (`ruby` bucket).
      A CVE id with a public PoC but **no published CVE record yet** (a reserved
      id the PoC author published first) is returned with a description starting
      `** UNPUBLISHED ** ` that summarises the evidence.
6.  (FREEMIUM) Enrich CVE/GHSA Identifiers (enrich) - `puncia enrich <cve-id/ghsa-id> <output-file>`
    - `enrich=true` only takes effect for `CVE-`/`GHSA-` identifiers; it merges
      the full upstream advisory record with EPSS + VEDAS scoring.
7.  (PAID) Non-CVE Identifiers by VEDAS group (noncve) - `puncia noncve <browser/china/russia/europe/exploitable> <output-file>`
8.  (PAID) Nuclei Template Candidates (nuclei) - `puncia nuclei candidates <output-file>`
    - CVEs that have a VEDAS id and **no nuclei template yet** but look
      templatable, highest priority first (`priority = feasibility × impact`).
      Each row carries a suggested template shape (protocol, method — `active`,
      `oast`, `version`, `fingerprint-first` — and whether it needs auth), PoC
      sources, portable afrog/xray/jaeles/goby templates, test environments,
      existing templates for the same product, and the reasons behind the score.
    - Every page is fetched and merged automatically; `--limit` sets the page
      size (max 1000) and `--offset` fetches exactly one page instead.
    - Narrow with repeatable `--filter KEY=VALUE`: `min_feasibility`, `vendor`,
      `product`, `platform`, `cwe`, `method`, `protocol`, `kev`, `poc`, `portable`.
    - **CSV export:** `--format csv`, or just give an output path ending in `.csv`
      — one row per CVE, list fields joined with `;` (reasons with ` | `), and
      cells that a spreadsheet would treat as a formula are made inert.
      ```bash
      puncia nuclei candidates candidates.csv
      puncia nuclei candidates wp.csv --filter platform=wordpress --filter poc=true
      puncia nuclei candidates --filter kev=true --filter min_feasibility=0.5 --format csv > kev.csv
      ```
9.  (FREE) Subdomain Center service health (^HEALTH) - `puncia subdomain ^HEALTH <output-file>`
10. Multiple Queries (bulk/sbom)

    - (FREEMIUM) Bulk Input JSON File Format - `puncia bulk <json-file> <output-directory>`
      ```json
      {
          "subdomain": [
              "domainA.com",
              "domainB.com"
          ],
          "replica": [
              "domainA.com",
              "domainB.com"
          ],
          "keyword": [
              "keywordA",
              "keywordB"
          ],
          "exploit": [
              "eoidentifierA",
              "eoidentifierB"
          ],
          "enrich": [
              "eoidentifierA",
              "eoidentifierB"
          ]
      }
      ```
    - (FREEMIUM) [SBOM Input JSON File Format](https://github.com/CycloneDX/bom-examples/blob/master/SBOM/protonmail-webclient-v4-0912dff/bom.json) - `puncia sbom <json-file> <output-directory>`

    Bulk and SBOM runs de-duplicate queries, cap parallelism at `--concurrency`
    (default 10), and — when no API key is present — pace requests to stay inside
    the free-tier budget automatically.

11. (FREEMIUM) External Import

   ```python
   import asyncio
   import puncia

   async def main():
      # Without an API key (ratelimited)
      print(await puncia.query_api("exploit", "CVE-2021-3450"))
      print(await puncia.query_api("subdomain", "arpsyndicate.io"))

      # With an API key
      await puncia.store_key("ARPS-xxxxxxxxxx")
      api_key = await puncia.read_key()
      print(await puncia.query_api("subdomain", "arpsyndicate.io", apikey=api_key))
      print(await puncia.query_api("replica", "arpsyndicate.io", match="exact", apikey=api_key))
      print(await puncia.query_api("enrich", "CVE-2021-3450", apikey=api_key))
      print(await puncia.query_api("noncve", "exploitable", apikey=api_key))

      # Nuclei template candidates: filtered, every page merged, saved as CSV
      candidates = await puncia.query_api(
          "nuclei", "candidates", "candidates.csv", apikey=api_key,
          filters={"platform": "wordpress", "poc": "true"}, output_format="csv",
      )
      print(puncia.candidates_to_csv(candidates))  # or render CSV yourself

      # Static endpoints (unauthenticated, unlimited)
      print(await puncia.query_api("subdomain", "^HEALTH"))
      print(await puncia.query_api("exploit", "^STATS"))

      # Live crawl, with the outcome surfaced via a callback
      await puncia.query_api(
          "subdomain", "bigco.com", apikey=api_key, crawl=True,
          on_crawl=lambda h: print("crawl status:", h.get("X-Crawl-Status")),
      )

      # Write straight to disk
      await puncia.query_api("subdomain", "arpsyndicate.io", "out.json", apikey=api_key)

   asyncio.run(main())
   ```

   Failures raise `puncia.PunciaError`; an empty result (`{}` / `[]`) is returned
   as-is rather than being treated as an error. Reuse one session across many
   queries by passing `session=` and a shared `limiter=`, exactly as
   `process_bulk()` does.

   ```python
   from puncia import PunciaError, query_api

   try:
       data = await query_api("exploit", "CVE-2021-3450", apikey=api_key)
   except PunciaError as exc:
       print(f"lookup failed: {exc}")
   ```

<br>

## Development

```bash
git clone https://github.com/ARPSyndicate/puncia && cd puncia
pip install --upgrade pip     # editable installs need pip >= 21.3
pip install -e ".[dev]"
pytest                        # 112 offline tests, no API calls or network access
```

The test suite is fully offline — it covers URL construction, output-path
containment, SBOM parsing, bulk planning and ratelimiter timing without touching
the network, so it is safe to run in any environment.



### CVE Enrichment 
<img src="https://raw.githubusercontent.com/ARPSyndicate/puncia/master/cve-enrich-diff.png" width="1500px">
<br>

### GHSA Enrichment 
<img src="https://raw.githubusercontent.com/ARPSyndicate/puncia/master/ghsa-enrich-diff.png" width="1500px">
<br>

## Noteworthy Mentions

- [Passive Subdomain Enumeration: Uncovering More Subdomains than Subfinder & Amass](https://osintteam.com/passive-subdomain-enumeration-uncovering-more-subdomains-than-subfinder-amass/)
- [Around 1000 exploitable cybersecurity vulnerabilities that MITRE & NIST ‘might’ have missed but China or Russia didn’t.](https://blog.arpsyndicate.io/over-a-1000-vulnerabilities-that-mitre-nist-might-have-missed-but-china-or-russia-did-not-871b2364a526)
- [Utilizing GitHub Actions for gathering Subdomain & Exploit Intelligence](https://blog.arpsyndicate.io/utilizing-github-actions-for-gathering-subdomain-exploit-intelligence-bbc79c19bb85)
- [Introducing Exploit Observer — More than Shodan Exploits, Less than Vulners](https://blog.arpsyndicate.io/introducing-exploit-observer-more-than-shodan-exploits-less-than-vulners-23eaea466e4a)
- [PUNCIA — The Panthera(P.)uncia of Cybersecurity](https://blog.arpsyndicate.io/puncia-the-panthera-p-uncia-of-cybersecurity-ft-puncia-subdomain-center-exploit-observer-9a9d8cca9576)
- [Subdomain Enumeration Tool Face-off - 2023 Edition](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off-4e5)
