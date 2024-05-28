#  The Panthera(P.)uncia of Cybersecurity 
### Official CLI utility for Subdomain Center & Exploit Observer

[![Downloads](https://pepy.tech/badge/puncia)](https://pepy.tech/project/puncia)
<img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
<img alt="GitHub stars" src="https://img.shields.io/github/stars/ARPSyndicate/puncia"> 
<br>
<img src="https://raw.githubusercontent.com/ARPSyndicate/puncia/master/puncia.png" width=25%> 
<br>
Puncia utilizes two of our intelligent APIs to gather the results - <br>
- [Subdomain Center - The World's Fastest Growing Subdomain & Shadow IT Intelligence Database](https://subdomain.center)<br>
- [Exploit Observer - The World's Largest Exploit & Vulnerability Intelligence Database](https://exploit.observer)

**Please note that although these results can sometimes be pretty inaccurate & unreliable, they can greatly differ from time to time due to their self-improvement capabilities.**

## Installation
1. From PyPi - `pip3 install puncia`
2. From Source - `pip3 install .`<br>

## Usage
1. Subdomain - `puncia subdomain <domain> <output-file>`
2. Exploit - `puncia exploit <eoidentifier> <output-file>`
3. Bulk - `puncia exploit <jsonfile> <output-directory>`<br>
### Bulk Input JSON Format
```
{
    "subdomain": [
        "domainA.com",
        "domainB.com"
    ],
    "exploit": [
        "eoidentifierA",
        "eoidentifierB"
    ]
}
```

## Supported EOIdentifiers
1. A.R.P. Syndicate Vulnerability & Exploit Data Aggregation System (VEDAS) - [`puncia exploit VEDAS:OBLIVIONHAWK`](https://api.exploit.observer/?keyword=VEDAS:OBLIVIONHAWK) 
2. Common Vulnerabilities and Exposures (CVE) - [`puncia exploit CVE-2021-3450`](https://api.exploit.observer/?keyword=CVE-2021-3450) 
3. Russian Data Bank of Information Security Threats (BDU) - [`puncia exploit BDU:2024-00390`](https://api.exploit.observer/?keyword=BDU:2024-00390)
4. China National Vulnerability Database (CNVD) - [`puncia exploit CNVD-2024-02713`](https://api.exploit.observer/?keyword=CNVD-2024-02713)
5. China National Vulnerability Database of Information Security (CNNVD) - [`puncia exploit CNNVD-202312-2255`](https://api.exploit.observer/?keyword=CNNVD-202312-2255)
6. Japan Vulnerability Notes iPedia (JVNDB) - [`puncia exploit JVNDB-2023-006199`](https://api.exploit.observer/?keyword=JVNDB-2023-006199) 
7. GitHub Security Advisories (GHSA) - [`puncia exploit GHSA-wfh5-x68w-hvw2`](https://api.exploit.observer/?keyword=GHSA-wfh5-x68w-hvw2)
8. GitHub Commits (GHCOMMIT) - [`puncia exploit GHCOMMIT-102448040d5132460e3b0013e03ebedec0677e00`](https://api.exploit.observer/?keyword=GHCOMMIT-102448040d5132460e3b0013e03ebedec0677e00) 
9. Veracode SourceClear Vulnerability Database (SRCCLR-SID) - [`puncia exploit SRCCLR-SID-3173`](https://api.exploit.observer/?keyword=SRCCLR-SID-3173)
10. Snyk Vulnerability Database (SNYK) - [`puncia exploit SNYK-JAVA-ORGCLOJURE-5740378`](https://api.exploit.observer/?keyword=SNYK-JAVA-ORGCLOJURE-5740378)
11. OffSec Exploit Database (EDB) - [`puncia exploit EDB-10102`](https://api.exploit.observer/?keyword=EDB-10102)
12. 0Day Today (0DAY-ID) - [`puncia exploit 0DAY-ID-24705`](https://api.exploit.observer/?keyword=0DAY-ID-24705)
13. Knownsec Seebug (SSVID) - [`puncia exploit SSVID-99817`](https://api.exploit.observer/?keyword=SSVID-99817)
14. Trend Micro Zero Day Initiative (ZDI) - [`puncia exploit ZDI-23-1714`](https://api.exploit.observer/?keyword=ZDI-23-1714) 
15. Packet Storm Security (PSS) - [`puncia exploit PSS-170615`](https://api.exploit.observer/?keyword=PSS-170615) 
16. CXSecurity World Laboratory of Bugtraq (WLB) - [`puncia exploit WLB-2024010058`](https://api.exploit.observer/?keyword=WLB-2024010058)
17. Rapid7 Metasploit Framework (MSF) - [`puncia exploit MSF/auxiliary_admin/2wire/xslt_password_reset`](https://api.exploit.observer/?keyword=MSF/auxiliary_admin/2wire/xslt_password_reset)
18. ProjectDiscovery Nuclei (PD) - [`puncia exploit PD/http/cves/2020/CVE-2020-12720`](https://api.exploit.observer/?keyword=PD/http/cves/2020/CVE-2020-12720) 
19. Hackerone Hacktivity (H1) - [`puncia exploit H1-2230915`](https://api.exploit.observer/?keyword=H1-2230915)
20. Cisco Talos (TALOS) - [`puncia exploit TALOS-2023-1896`](https://api.exploit.observer/?keyword=TALOS-2023-1896)
21. ProtectAI Huntr (HUNTR) - [`puncia exploit HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5`](https://api.exploit.observer/?keyword=HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5)
22. WP Engine WPScan (WPSCAN) - [`puncia exploit WPSCAN-52568abd-c509-411e-8391-c75e7613eb42`](https://api.exploit.observer/?keyword=WPSCAN-52568abd-c509-411e-8391-c75e7613eb42)
23. Defiant Wordfence (WORDFENCE) - [`puncia exploit WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85`](https://api.exploit.observer/?keyword=WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85)
24. YouTube (YT) - [`puncia exploit YT/ccqjhUmwLCk`](https://api.exploit.observer/?keyword=YT/ccqjhUmwLCk)
25. Zero Science Lab (ZSL) - [`puncia exploit ZSL-2022-5743`](https://api.exploit.observer/?keyword=ZSL-2022-5743)
26. VARIoT Exploits (VAR-E) - [`puncia exploit VAR-E-201704-0525`](https://api.exploit.observer/?keyword=VAR-E-201704-0525)
27. VARIoT Vulnerabilities (VAR) - [`puncia exploit VAR-202404-0085`](https://api.exploit.observer/?keyword=VAR-202404-0085)
28. Russian VIDs with no associated CVEs (^RU_NON_CVE) - [`puncia exploit ^RU_NON_CVE`](http://api.exploit.observer/russia/noncve)<br>
29. Chinese VIDs with no associated CVEs (^CN_NON_CVE) - [`puncia exploit ^CN_NON_CVE`](http://api.exploit.observer/china/noncve)<br>
30. Vendor/Product (No Prefix) - [`puncia exploit grafana`](https://api.exploit.observer/?keyword=grafana)<br>
31. Vendor/Product + Version (No Prefix) - [`puncia exploit felixwelberg@1.0.45`](https://api.exploit.observer/?keyword=felixwelberg@1.0.45)<br>


## Noteworthy Mentions
- [Around 1000 exploitable cybersecurity vulnerabilities that MITRE & NIST ‘might’ have missed but China or Russia didn’t.](https://blog.arpsyndicate.io/over-a-1000-vulnerabilities-that-mitre-nist-might-have-missed-but-china-or-russia-did-not-871b2364a526)
- [Utilizing GitHub Actions for gathering Subdomain & Exploit Intelligence](https://blog.arpsyndicate.io/utilizing-github-actions-for-gathering-subdomain-exploit-intelligence-bbc79c19bb85)
- [Introducing Exploit Observer — More than Shodan Exploits, Less than Vulners](https://blog.arpsyndicate.io/introducing-exploit-observer-more-than-shodan-exploits-less-than-vulners-23eaea466e4a)
- [PUNCIA — The Panthera(P.)uncia of Cybersecurity](https://blog.arpsyndicate.io/puncia-the-panthera-p-uncia-of-cybersecurity-ft-puncia-subdomain-center-exploit-observer-9a9d8cca9576)
- [Subdomain Enumeration Tool Face-off - 2023 Edition](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off-4e5)

## More from [A.R.P. Syndicate](https://www.arpsyndicate.io)
- [Attack Surface Management](https://asm.arpsyndicate.io)
- [Open Source Intelligence](https://asm.arpsyndicate.io/intelligence.html)
- [Free Vulnerability Assessment Report](https://asm.arpsyndicate.io/free-vulnerability-scanning.html)