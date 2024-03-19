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
        "eoidentifierA"
    ]
}
```

## Supported EOIdentifiers
1. Common Vulnerabilities and Exposures (CVE) - [`puncia exploit CVE-2021-3450`](https://api.exploit.observer/?keyword=CVE-2021-3450) 
2. Russian Data Bank of Information Security Threats (BDU) - [`puncia exploit BDU:2024-00390`](https://api.exploit.observer/?keyword=BDU:2024-00390)
3. China National Vulnerability Database (CNVD) - [`puncia exploit CNVD-2024-02713`](https://api.exploit.observer/?keyword=CNVD-2024-02713)
4. China National Vulnerability Database of Information Security (CNNVD) - [`puncia exploit CNNVD-202312-2255`](https://api.exploit.observer/?keyword=CNNVD-202312-2255)
5. Japan Vulnerability Notes iPedia (JVNDB) - [`puncia exploit JVNDB-2023-006199`](https://api.exploit.observer/?keyword=JVNDB-2023-006199) 
6. GitHub Security Advisories (GHSA) - [`puncia exploit GHSA-wfh5-x68w-hvw2`](https://api.exploit.observer/?keyword=GHSA-wfh5-x68w-hvw2) 
7. CSA Global Security Database (GSD) - [`puncia exploit GSD-2021-3450`](https://api.exploit.observer/?keyword=GSD-2021-3450)
8. OffSec Exploit Database (EDB) - [`puncia exploit EDB-10102`](https://api.exploit.observer/?keyword=EDB-10102)
9. Knownsec Seebug (SSVID) - [`puncia exploit SSVID-99817`](https://api.exploit.observer/?keyword=SSVID-99817)
10. Trend Micro Zero Day Initiative (ZDI) - [`puncia exploit ZDI-23-1714`](https://api.exploit.observer/?keyword=ZDI-23-1714) 
11. Packet Storm Security (PSS) - [`puncia exploit PSS-170615`](https://api.exploit.observer/?keyword=PSS-170615) 
12. CXSecurity World Laboratory of Bugtraq (WLB) - [`puncia exploit WLB-2024010058`](https://api.exploit.observer/?keyword=WLB-2024010058)
13. Rapid7 Metasploit Framework (MSF) - [`puncia exploit MSF/auxiliary_admin/2wire/xslt_password_reset`](https://api.exploit.observer/?keyword=MSF/auxiliary_admin/2wire/xslt_password_reset)
14. ProjectDiscovery Nuclei (PD) - [`puncia exploit PD/http/cves/2020/CVE-2020-12720`](https://api.exploit.observer/?keyword=PD/http/cves/2020/CVE-2020-12720) 
15. Hackerone Hacktivity (H1) - [`puncia exploit H1-2230915`](https://api.exploit.observer/?keyword=H1-2230915)
16. Cisco Talos (TALOS) - [`puncia exploit TALOS-2023-1896`](https://api.exploit.observer/?keyword=TALOS-2023-1896)
17. ProtectAI Huntr (HUNTR) - [`puncia exploit HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5`](https://api.exploit.observer/?keyword=HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5)
18. WP Engine WPScan (WPSCAN) - [`puncia exploit WPSCAN-52568abd-c509-411e-8391-c75e7613eb42`](https://api.exploit.observer/?keyword=WPSCAN-52568abd-c509-411e-8391-c75e7613eb42)
19. Defiant Wordfence (WORDFENCE) - [`puncia exploit WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85`](https://api.exploit.observer/?keyword=WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85)
20. YouTube (YT) - [`puncia exploit YT/ccqjhUmwLCk`](https://api.exploit.observer/?keyword=YT/ccqjhUmwLCk)
21. Technologies/Keywords (No Prefix) - [`puncia exploit grafana`](https://api.exploit.observer/?keyword=grafana)<br>


## Noteworthy Mentions
- [Introducing Exploit Observer — More than Shodan Exploits, Less than Vulners](https://blog.arpsyndicate.io/introducing-exploit-observer-more-than-shodan-exploits-less-than-vulners-23eaea466e4a)
- [PUNCIA — The Panthera(P.)uncia of Cybersecurity](https://blog.arpsyndicate.io/puncia-the-panthera-p-uncia-of-cybersecurity-ft-puncia-subdomain-center-exploit-observer-9a9d8cca9576)
- [Subdomain Enumeration Tool Face-off - 2023 Edition](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off-4e5)

## More from [A.R.P. Syndicate](https://www.arpsyndicate.io)
- [Attack Surface Management](https://asm.arpsyndicate.io)
- [Open Source Intelligence](https://asm.arpsyndicate.io/intelligence.html)
- [Free Vulnerability Assessment Report](https://asm.arpsyndicate.io/free-vulnerability-scanning.html)