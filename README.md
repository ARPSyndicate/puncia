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

## Practical Applications

1. **Mapping External Attack Surfaces**  
   Identify and monitor exposed subdomains and infrastructure components across the internet.
2. **Advanced Vulnerability Research & Monitoring**  
   Discover and track known and emerging threats, including obscure or unlisted vulnerabilities.
3. **Contextual Enrichment of CVE/GHSA Data**  
   Add depth and actionable intelligence to known vulnerabilities for better prioritization.
4. **LLM-Driven Summarization & Prompt Execution**  
   Leverage AI to summarize web content or generate code and analysis based on natural language prompts.
5. **Automated Vulnerability Advisory Creation**  
   Instantly generate detailed, multilingual security advisories for discovered vulnerabilities.
6. **Vulnerability Detection in Software Bill of Materials (SBOM)**  
   Analyze software components for known exploits and security issues using structured SBOM data.
7. **Seamless Integration with CI/CD & Threat Intel Workflows**  
   Automate intelligence gathering and vulnerability checks within development or security pipelines.
8. **Monitoring Nation-State Exploit Trends**  
   Stay ahead of threats by tracking vulnerabilities flagged by foreign actors but not yet recognized by mainstream databases.
9. **Replica Domain Detection & Brand Protection**  
   Identify replica or lookalike domains that could be used in phishing or impersonation attacks.
10. **Bulk Threat Intelligence Processing**  
   Run batch queries (domains, vulnerabilities, etc.) for scalable analysis across large datasets or enterprise asset inventories.
11. **Passive Reconnaissance for Red Teams**  
   Conduct stealthy reconnaissance by using passive data sources (no direct interaction with targets).
12. **Open Source Intelligence (OSINT) Collection**  
   Combine subdomain, exploit, and content summarization features to enhance OSINT investigations.
13. **Security Blog & Research Digest Automation**  
   Automatically summarize technical blog posts and reports into actionable briefs.
14. **Cross-Language Security Intelligence Delivery**  
   Translate advisories or technical content into other languages for global teams and multilingual incident response.
15. **Compliance & Risk Management Support**  
   Enrich vulnerability data to support compliance audits (e.g., ISO 27001, SOC 2) with deeper context.


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
7.  (PAID) Generate Vulnerability Advisory with the LLM (advisory) - `puncia advisory "<eoidentifier>|<language>" <output-file>`
8.  (FREEMIUM) Enrich CVE/GHSA Identifiers (enrich) - `puncia enrich <cve-id/ghsa-id> <output-file>`
9.  Multiple Queries (bulk/sbom)

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
          "exploit": [
              "eoidentifierA",
              "eoidentifierB"
          ],
          "enrich": [
              "eoidentifierA",
              "eoidentifierB"
          ],
          "advisory": [
              "eoidentifierA",
              "eoidentifierB|GERMAN"
          ]
      }
      ```
    - (FREEMIUM) [SBOM Input JSON File Format](https://github.com/CycloneDX/bom-examples/blob/master/SBOM/protonmail-webclient-v4-0912dff/bom.json) - `puncia sbom <json-file> <output-directory>`

10.  (FREEMIUM) External Import

   ```python
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
      print(await puncia.query_api("advisory", "CVE-2025-31324", apikey=api_key))
      print(await puncia.query_api("advisory", "CVE-2025-31324|FRENCH", apikey=api_key))

   # Run the main async function
   asyncio.run(main())
   ```

<br>

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

## More from [A.R.P. Syndicate](https://www.arpsyndicate.io)

- [VEDAS Advisories](https://vedas.arpsyndicate.io)
- [Open Source Intelligence](https://asm.arpsyndicate.io/intelligence.html)
- [Attack Surface Management](https://asm.arpsyndicate.io)
