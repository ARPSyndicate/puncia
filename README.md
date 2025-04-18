# Panthera(P.)uncia

### Official CLI utility for Osprey Vision, Subdomain Center & Exploit Observer

[![Downloads](https://pepy.tech/badge/puncia)](https://pepy.tech/project/puncia)
<img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
<img alt="GitHub stars" src="https://img.shields.io/github/stars/ARPSyndicate/puncia">
<br>
<img src="https://raw.githubusercontent.com/ARPSyndicate/puncia/master/puncia.png" width=25%>
<br>
Puncia utilizes three of our intelligent APIs to gather the results - <br>

- [Subdomain Center - The World's Largest Subdomain & Shadow IT Intelligence Database](https://subdomain.center)<br>
- [Exploit Observer - The World's Largest Exploit & Vulnerability Intelligence Database](https://exploit.observer)<br>
- [Osprey Vision - The World's Most Bleeding Edge AI for Information Discovery](https://osprey.vision)

**Please note that although these results can sometimes be pretty inaccurate & unreliable, they can greatly differ from time to time due to their self-improvement capabilities.**

**Aggressive rate-limits can be avoided with an API key: https://www.arpsyndicate.io/pricing.html**

## Installation

1. From PyPi - `pip3 install puncia`
2. From Source - `pip3 install .`<br>

## Usage

1.  (PAID) Store an API key (storekey) - `puncia storekey <api-key>`
2.  (FREEMIUM) Interact with the LLM (chat) - `puncia chat "<prompt>" <output-file>`
3.  (PAID) Summarize Webpages with the LLM (summarize) - `puncia summarize "<links>" <output-file>`
4.  (FREEMIUM) Query Domains (subdomain) - `puncia subdomain <domain> <output-file>`
5.  (FREEMIUM) Query Replica Domains (replica) - `puncia replica <domain> <output-file>`
6.  Query Exploit & Vulnerability Identifiers (exploit)
    - (FREE) Russian VIDs with no associated CVEs (^RU_NON_CVE) - `puncia exploit ^RU_NON_CVE  <output-file>` 
    - (FREE) Chinese VIDs with no associated CVEs (^CN_NON_CVE) - `puncia exploit ^CN_NON_CVE  <output-file>`
    - (FREE) Vulnerability & Exploit Identifers Watchlist (^WATCHLIST_IDES) - `puncia exploit ^WATCHLIST_IDES  <output-file>`
    - (FREE) Vulnerability & Exploit Identifers Watchlist with Descriptions (^WATCHLIST_INFO) - `puncia exploit ^WATCHLIST_INFO  <output-file>`
    - (FREE) Vulnerable Technologies Watchlist (^WATCHLIST_TECH) - `puncia exploit ^WATCHLIST_TECH  <output-file>`
    - (FREEMIUM) [Supported Vulnerability Identifiers](https://github.com/ARPSyndicate/docs?tab=readme-ov-file#supported-vulnerability-identifiers) - `puncia exploit <eoidentifier> <output-file>`
7.  (FREEMIUM) Enrich CVE/GHSA Identifiers (enrich) - `puncia enrich <cve-id/ghsa-id> <output-file>`
8.  Multiple Queries (bulk/sbom)

    - (FREEMIUM) Bulk Input JSON File Format - `puncia bulk <json-file> <output-directory>`
      ```
      {
          "subdomain": [
              "domainA.com",
              "domainB.com"
          ],
          "replica": [
              "domainA.com",
              "domainB.com"
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

9.  (FREEMIUM) External Import

    ```
        import puncia
        import asyncio

        async def main():
            # Without API Key
            print(await puncia.query_api("exploit", "CVE-2021-3450"))
            print(await puncia.query_api("subdomain", "arpsyndicate.io"))
            print(await puncia.query_api("chat", "write a xss fuzzer in python"))

            # With API Key
            await puncia.store_key("ARPS-xxxxxxxxxx")
            api_key = await puncia.read_key()
            print(await puncia.query_api("subdomain", "arpsyndicate.io", apikey=api_key))
            print(await puncia.query_api("exploit", "CVE-2021-3450", apikey=api_key))
            print(await puncia.query_api("chat", "write a xss fuzzer in python", apikey=api_key))
            print(await puncia.query_api("summarize", "https://www.osintteam.com/combating-the-darkest-depths-of-cyber-intelligence-the-pall-mall-process/", apikey=api_key))

        # Run the main async function
        asyncio.run(main())

    ```

<br>

## Noteworthy Mentions

- [Passive Subdomain Enumeration: Uncovering More Subdomains than Subfinder & Amass](https://osintteam.com/passive-subdomain-enumeration-uncovering-more-subdomains-than-subfinder-amass/)
- [Around 1000 exploitable cybersecurity vulnerabilities that MITRE & NIST ‘might’ have missed but China or Russia didn’t.](https://blog.arpsyndicate.io/over-a-1000-vulnerabilities-that-mitre-nist-might-have-missed-but-china-or-russia-did-not-871b2364a526)
- [Utilizing GitHub Actions for gathering Subdomain & Exploit Intelligence](https://blog.arpsyndicate.io/utilizing-github-actions-for-gathering-subdomain-exploit-intelligence-bbc79c19bb85)
- [Introducing Exploit Observer — More than Shodan Exploits, Less than Vulners](https://blog.arpsyndicate.io/introducing-exploit-observer-more-than-shodan-exploits-less-than-vulners-23eaea466e4a)
- [PUNCIA — The Panthera(P.)uncia of Cybersecurity](https://blog.arpsyndicate.io/puncia-the-panthera-p-uncia-of-cybersecurity-ft-puncia-subdomain-center-exploit-observer-9a9d8cca9576)
- [Subdomain Enumeration Tool Face-off - 2023 Edition](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off-4e5)

## More from [A.R.P. Syndicate](https://www.arpsyndicate.io)

- [VEDAS Advisories](https://vedas.arpsyndicate.io)
- [Open Source Intelligence](https://asm.arpsyndicate.io/intelligence.html)
- [Attack Surface Management](https://asm.arpsyndicate.io)
