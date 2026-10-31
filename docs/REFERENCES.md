# References

_Generated from [`references.yml`](references.yml) by `tools/build_references.py`. Do not edit by hand._

Citations use APA 7 style. Sources are kept to roughly the last 4 years: CI and a weekly scheduled workflow flag any non-evergreen source that ages out, so it gets replaced or re-confirmed. Living resources (ATT&CK technique pages, vendor documentation, the Sigma specification) are linked from each playbook and treated as evergreen.

## Peer-reviewed and academic

- <a id="badva-2024"></a>Badva, P., Ramokapane, K. M., Pantano, E., & Rashid, A. (2024). *Unveiling the hunter-gatherers: Exploring threat hunting practices and challenges in cyber defense*. 33rd USENIX Security Symposium (USENIX Security '24). <https://www.usenix.org/conference/usenixsecurity24/presentation/badva>  
  `[badva-2024]` · used by: kit-wide
- <a id="isik-2025"></a>Işık, B., Tuncer, B. İ., Amirov, N., & Bahtiyar, Ş. (2025). *DNS tunneling: Threat landscape and improved detection solutions*. arXiv preprint arXiv:2507.10267. <https://arxiv.org/abs/2507.10267>  
  `[isik-2025]` · used by: [HL-0014](../playbooks/HL-0014-T1071.004-dns-c2-beaconing.md)
- <a id="mahboubi-2024"></a>Mahboubi, A., Luong, K., Aboutorab, H., Bui, H. T., Jarrad, G., Bahutair, M., Camtepe, S., Pogrebna, G., Ahmed, E., Barry, B., & Gately, H. (2024). *Evolving techniques in cyber threat hunting: A systematic review*. Journal of Network and Computer Applications, 232, 104004. <https://researchr.org/publication/MahboubiLABJBCPABG24>  
  `[mahboubi-2024]` · used by: kit-wide
- <a id="milani-2024"></a>Milani, A. M. P., Starr, A., Hill, S., Curtis, C., Anderson, N., Moreno-Lumbreras, D., & Storey, M.-A. (2024). *Fuzzy to clear: Elucidating the threat hunter cognitive process and cognitive support needs*. arXiv preprint arXiv:2408.04348. <https://arxiv.org/abs/2408.04348>  
  `[milani-2024]` · used by: kit-wide
- <a id="wang-2022"></a>Wang, Z. (2022). *A systematic literature review on cyber threat hunting*. arXiv preprint arXiv:2212.05310. <https://arxiv.org/abs/2212.05310>  
  `[wang-2022]` · used by: kit-wide

## Standards and frameworks

- <a id="attack-v19"></a>MITRE (2026). *ATT&CK v19 release notes (Defense Evasion split into Stealth and Defense Impairment)*. MITRE ATT&CK. <https://attack.mitre.org/resources/updates/updates-april-2026/>  
  `[attack-v19]` · used by: kit-wide
- <a id="nist-800-61r3"></a>Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile (NIST SP 800-61r3)*. National Institute of Standards and Technology. <https://csrc.nist.gov/pubs/sp/800/61/r3/final>  
  `[nist-800-61r3]` · used by: kit-wide
- <a id="sigma-spec"></a>SigmaHQ (2024). *Sigma specification (rules, correlations, filters)*. GitHub, SigmaHQ/sigma-specification. <https://github.com/SigmaHQ/sigma-specification>  
  `[sigma-spec]` · used by: kit-wide

## Government advisories and guidance

- <a id="cisa-aa23-061a"></a>CISA & FBI (2024). *#StopRansomware: BlackSuit (Royal) ransomware (AA23-061A), updated August 2024*. Joint cybersecurity advisory. <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a>  
  `[cisa-aa23-061a]` · used by: [HL-0005](../playbooks/HL-0005-T1047-T1021.002-wmi-psexec-lateral-movement.md), [HL-0007](../playbooks/HL-0007-T1490-inhibit-system-recovery.md), [HL-0009](../playbooks/HL-0009-T1021.001-rdp-lateral-movement.md)
- <a id="cisa-aa23-320a"></a>CISA & FBI (2025). *Scattered Spider (AA23-320A), revised July 2025*. Joint cybersecurity advisory. <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>  
  `[cisa-aa23-320a]` · used by: [HL-0010](../playbooks/HL-0010-T1567.002-exfiltration-to-cloud-storage.md), [HL-0012](../playbooks/HL-0012-T1621-mfa-fatigue.md)
- <a id="cisa-ransomware-guide"></a>CISA, FBI, NSA, & MS-ISAC (2023). *#StopRansomware guide*. Cybersecurity and Infrastructure Security Agency. <https://www.cisa.gov/stopransomware/ransomware-guide>  
  `[cisa-ransomware-guide]` · used by: [HL-0001](../playbooks/HL-0001-T1059.001-encoded-powershell.md), [HL-0007](../playbooks/HL-0007-T1490-inhibit-system-recovery.md)
- <a id="cisa-lotl-2024"></a>CISA, NSA, FBI, & international partners (2024). *Identifying and mitigating living off the land techniques*. Joint guidance. <https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques>  
  `[cisa-lotl-2024]` · used by: [HL-0001](../playbooks/HL-0001-T1059.001-encoded-powershell.md), [HL-0002](../playbooks/HL-0002-T1003.001-lsass-credential-dumping.md), [HL-0003](../playbooks/HL-0003-T1053.005-scheduled-task-persistence.md), [HL-0004](../playbooks/HL-0004-T1547.001-registry-run-keys.md), [HL-0005](../playbooks/HL-0005-T1047-T1021.002-wmi-psexec-lateral-movement.md), [HL-0008](../playbooks/HL-0008-T1218-lolbin-proxy-execution.md)

## Industry research

- <a id="peak-2023"></a>Bianco, D., & Splunk SURGe (2023). *Introducing the PEAK threat hunting framework*. Splunk Security Blog. <https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html>  
  `[peak-2023]` · used by: kit-wide
- <a id="elastic-linux-persistence-2024"></a>Groenewoud, R. (2024). *Linux detection engineering: A primer on persistence mechanisms*. Elastic Security Labs. <https://www.elastic.co/security-labs/primer-on-persistence-mechanisms>  
  `[elastic-linux-persistence-2024]` · used by: [HL-0013](../playbooks/HL-0013-T1053.003-T1543.002-linux-cron-systemd-persistence.md)
- <a id="ms-kerberoasting-2024"></a>Microsoft (2024). *Microsoft's guidance to help mitigate Kerberoasting*. Microsoft Security Blog. <https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/>  
  `[ms-kerberoasting-2024]` · used by: [HL-0006](../playbooks/HL-0006-T1558.003-kerberoasting.md)
- <a id="ms-lsass-2022"></a>Microsoft Threat Intelligence (2022). *Detecting and preventing LSASS credential dumping attacks*. Microsoft Security Blog. <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/>  
  `[ms-lsass-2022]` · used by: [HL-0002](../playbooks/HL-0002-T1003.001-lsass-credential-dumping.md)
- <a id="ms-midnight-blizzard-2024"></a>Microsoft Threat Intelligence (2024). *Midnight Blizzard: Guidance for responders on nation-state attack*. Microsoft Security Blog. <https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/>  
  `[ms-midnight-blizzard-2024]` · used by: [HL-0011](../playbooks/HL-0011-T1528-oauth-consent-abuse.md)
- <a id="sans-2026"></a>SANS Institute (2026). *SANS 2026 threat hunting survey: Data quality overtakes staffing as the top barrier*. SANS Institute press release and survey report. <https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds>  
  `[sans-2026]` · used by: kit-wide

## How to add a source

1. Add an entry to `docs/references.yml` (prefer peer-reviewed, government or standards bodies; published within 4 years).
2. Cite it in the playbook's *References* section.
3. Run `python tools/build_references.py` and commit both files.
