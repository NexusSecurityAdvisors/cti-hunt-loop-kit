# CTI Hunt Loop Kit

<p align="center"><img src="assets/hunt-loop-banner.svg" alt="CTI Hunt Loop Kit: an animated six-stage loop from intel collection to feedback" width="100%"></p>

<p align="center">
<a href="https://github.com/NexusSecurityAdvisors/cti-hunt-loop-kit/actions/workflows/validate.yml"><img alt="Validate" src="https://github.com/NexusSecurityAdvisors/cti-hunt-loop-kit/actions/workflows/validate.yml/badge.svg"></a>
<a href="https://github.com/NexusSecurityAdvisors/cti-hunt-loop-kit/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/NexusSecurityAdvisors/cti-hunt-loop-kit/actions/workflows/codeql.yml/badge.svg"></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/NexusSecurityAdvisors/cti-hunt-loop-kit"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/NexusSecurityAdvisors/cti-hunt-loop-kit/badge"></a>
<img alt="MITRE ATT&CK v20" src="https://img.shields.io/badge/MITRE_ATT%26CK-v20-red">
<img alt="Python 3.14" src="https://img.shields.io/badge/python-3.14-blue">
<a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-green"></a>
<a href="CITATION.cff"><img alt="Cite this kit" src="https://img.shields.io/badge/cite-CITATION.cff-lightgrey"></a>
</p>

**Watch the 65-second overview:**

https://github.com/user-attachments/assets/1cf4a2cb-78ad-4b53-9258-703f8cec299e

**Intel-driven threat hunting, closed-loop.** A practical kit for turning cyber threat intelligence into testable hunt hypotheses, executing hunts across common SIEM/EDR platforms, and feeding what you find back into your intelligence and detection programs.

> Developed as companion material for a proposed FIRST CTI 2027 workshop and the book *Advanced Cyber Threat Intelligence and Hunting* (Dan Sorensen & Gianluca Tiepolo).

---

## Why a "loop"?

Most teams treat CTI and threat hunting as separate lanes: intel produces reports, hunters produce one-off queries, and the lessons rarely flow back. The Hunt Loop makes the hand-offs explicit so every hunt either **produces a detection**, **improves the intel**, or **retires a bad hypothesis** — and every outcome is recorded.

```mermaid
flowchart LR
    A[1. Collect & Prioritize Intel<br/>PIRs, reports, ATT&CK] --> B[2. Hypothesize<br/>Hunt hypothesis card]
    B --> C[3. Hunt<br/>Sigma / KQL / SPL]
    C --> D[4. Analyze & Triage<br/>Findings, false positives]
    D --> E[5. Operationalize<br/>Detections, playbooks]
    E --> F[6. Feed Back<br/>Intel updates, new PIRs]
    F --> A
```

| Stage | Question it answers | Kit artifact |
|---|---|---|
| 1. Collect & Prioritize | What threats matter to *us* right now? | `templates/pir-worksheet.md` |
| 2. Hypothesize | What would that adversary behavior look like in our telemetry? | `templates/hypothesis-card.md` |
| 3. Hunt | Where and how do we look? | `queries/` (Sigma, KQL, SPL) |
| 4. Analyze | What did we find, and how confident are we? | `templates/hunt-report.md` |
| 5. Operationalize | How do we catch this automatically next time? | `detections/` |
| 6. Feed Back | What did we learn that changes our intel? | `templates/intel-feedback.md` |

## Research basis

The loop applies what recent research says separates effective hunt programs from ad-hoc querying. Full bibliography, kept to sources from roughly the last four years and checked automatically: [`docs/REFERENCES.md`](docs/REFERENCES.md).

- **Hypothesis-driven, repeatable hunts.** Systematic reviews map the field from manual, hypothesis-driven hunting to data-driven and ML-assisted methods, and both stress documented, repeatable processes ([Wang, 2022](docs/REFERENCES.md#wang-2022); [Mahboubi et al., 2024](docs/REFERENCES.md#mahboubi-2024)). The hypothesis card and playbook structure follow the prepare / execute / act phases of the [PEAK framework](docs/REFERENCES.md#peak-2023).
- **Practitioner reality.** Interviews with 22 experienced hunters found their everyday challenges are as much about people and organizational culture as about technology ([Badva et al., USENIX Security 2024](docs/REFERENCES.md#badva-2024)); hunters move from a "fuzzy" lead to a clear hypothesis and need structured support to do it ([Milani et al., 2024](docs/REFERENCES.md#milani-2024)). The templates, triage questions and *Inconclusive (data gap)* outcome exist for these reasons.
- **Measure outcomes, not activity.** In the 2026 SANS survey, data quality overtook skilled staff as hunters' top barrier for the first time, 50% vs. 45% ([SANS, 2026](docs/REFERENCES.md#sans-2026)), which is why the metrics track data gaps found and closed.
- **Feed incident response.** Hunt findings map to the *Detect* and *Respond* functions of the NIST CSF 2.0 incident-response profile ([NIST SP 800-61r3, 2025](docs/REFERENCES.md#nist-800-61r3)).
- **Current adversary tradecraft.** Each playbook cites recent CISA joint advisories and vendor research for the behaviour it hunts (for example [Scattered Spider, rev. 2025](docs/REFERENCES.md#cisa-aa23-320a) for MFA fatigue and MEGA exfiltration, and [living-off-the-land guidance, 2024](docs/REFERENCES.md#cisa-lotl-2024) for LOLBin and PowerShell hunts).

## Repository layout

```
cti-hunt-loop-kit/
├── templates/          # PIR worksheet, hypothesis card, hunt report, intel feedback form
├── playbooks/          # ATT&CK-mapped hunt playbooks (one per technique / campaign)
├── queries/
│   ├── sigma/          # Platform-agnostic rules
│   ├── kql/            # Microsoft Sentinel / Defender XDR
│   └── spl/            # Splunk
├── detections/         # Promotion criteria for turning hunts into production detections
├── data/               # Synthetic lab dataset (Sysmon/Security JSONL + Defender/Sentinel CSV) and generator
├── workshop/           # Attendee lab guide and exercises (facilitator guide is private)
├── metrics/            # Hunt program tracker (CSV) and KPI script
├── navigator/          # ATT&CK Navigator coverage layer and coverage table (generated)
├── tools/              # Navigator layer, bibliography and demo-GIF generators
├── docs/               # Bibliography (references.yml → REFERENCES.md)
├── assets/             # Animated banner, terminal demo, explainer video
├── tests/              # Sigma rules vs. lab answer key; repo consistency checks
├── .python-version     # Python version used everywhere (3.14)
├── requirements.txt    # Pinned Sigma tooling for CI, tests and the workshop (Python 3.14)
└── CHANGELOG.md        # Release notes
```

> **Status:** v1.3. Fourteen ATT&CK-mapped playbooks covering Windows, Linux, DNS and Microsoft Entra ID, each with Sigma, KQL and SPL. Also includes a synthetic lab dataset, a full workshop, a metrics tracker and an ATT&CK Navigator coverage layer. See the roadmap below.

## Playbooks

Together, the playbooks follow a typical human-operated ransomware intrusion, from the first compromised identity in the cloud to encryption of Windows and Linux hosts. Coverage by tactic and technique is in [`navigator/COVERAGE.md`](navigator/COVERAGE.md), and there is an [ATT&CK Navigator layer](navigator/cti-hunt-loop-kit.layer.json) you can load.

| ID | Hunt | ATT&CK | Difficulty | Queries |
|---|---|---|---|---|
| [HL-0001](playbooks/HL-0001-T1059.001-encoded-powershell.md) | Encoded PowerShell & download cradles | T1059.001, T1027, T1105 | Beginner | [Sigma](queries/sigma/hl-0001_encoded_powershell.yml) · [KQL](queries/kql/hl-0001_encoded_powershell.kql) · [SPL](queries/spl/hl-0001_encoded_powershell.spl) |
| [HL-0002](playbooks/HL-0002-T1003.001-lsass-credential-dumping.md) | LSASS credential dumping | T1003.001 | Intermediate | [Sigma](queries/sigma/hl-0002_lsass_credential_dumping.yml) · [KQL](queries/kql/hl-0002_lsass_credential_dumping.kql) · [SPL](queries/spl/hl-0002_lsass_credential_dumping.spl) |
| [HL-0003](playbooks/HL-0003-T1053.005-scheduled-task-persistence.md) | Scheduled task persistence | T1053.005 | Beginner | [Sigma](queries/sigma/hl-0003_scheduled_task_persistence.yml) · [KQL](queries/kql/hl-0003_scheduled_task_persistence.kql) · [SPL](queries/spl/hl-0003_scheduled_task_persistence.spl) |
| [HL-0004](playbooks/HL-0004-T1547.001-registry-run-keys.md) | Registry Run key persistence | T1547.001, T1112 | Beginner | [Sigma](queries/sigma/hl-0004_registry_run_keys.yml) · [KQL](queries/kql/hl-0004_registry_run_keys.kql) · [SPL](queries/spl/hl-0004_registry_run_keys.spl) |
| [HL-0005](playbooks/HL-0005-T1047-T1021.002-wmi-psexec-lateral-movement.md) | WMI / PsExec lateral movement | T1047, T1021.002, T1569.002 | Intermediate | [Sigma](queries/sigma/hl-0005_wmi_psexec_lateral_movement.yml) · [KQL](queries/kql/hl-0005_wmi_psexec_lateral_movement.kql) · [SPL](queries/spl/hl-0005_wmi_psexec_lateral_movement.spl) |
| [HL-0006](playbooks/HL-0006-T1558.003-kerberoasting.md) | Kerberoasting | T1558.003 | Intermediate | [Sigma](queries/sigma/hl-0006_kerberoasting.yml) · [KQL](queries/kql/hl-0006_kerberoasting.kql) · [SPL](queries/spl/hl-0006_kerberoasting.spl) |
| [HL-0007](playbooks/HL-0007-T1490-inhibit-system-recovery.md) | Inhibit system recovery | T1490 | Beginner | [Sigma](queries/sigma/hl-0007_inhibit_system_recovery.yml) · [KQL](queries/kql/hl-0007_inhibit_system_recovery.kql) · [SPL](queries/spl/hl-0007_inhibit_system_recovery.spl) |
| [HL-0008](playbooks/HL-0008-T1218-lolbin-proxy-execution.md) | LOLBin proxy execution (mshta, regsvr32, rundll32) | T1218.005, .010, .011 | Beginner | [Sigma](queries/sigma/hl-0008_lolbin_proxy_execution.yml) · [KQL](queries/kql/hl-0008_lolbin_proxy_execution.kql) · [SPL](queries/spl/hl-0008_lolbin_proxy_execution.spl) |
| [HL-0009](playbooks/HL-0009-T1021.001-rdp-lateral-movement.md) | RDP lateral movement | T1021.001, T1078 | Intermediate | [Sigma](queries/sigma/hl-0009_rdp_lateral_movement.yml) · [KQL](queries/kql/hl-0009_rdp_lateral_movement.kql) · [SPL](queries/spl/hl-0009_rdp_lateral_movement.spl) |
| [HL-0010](playbooks/HL-0010-T1567.002-exfiltration-to-cloud-storage.md) | Exfiltration to cloud storage (rclone, MEGA) | T1567.002 | Intermediate | [Sigma](queries/sigma/hl-0010_exfiltration_to_cloud_storage.yml) · [KQL](queries/kql/hl-0010_exfiltration_to_cloud_storage.kql) · [SPL](queries/spl/hl-0010_exfiltration_to_cloud_storage.spl) |
| [HL-0011](playbooks/HL-0011-T1528-oauth-consent-abuse.md) | OAuth illicit consent grant (Entra ID) | T1528, T1550.001 | Intermediate | [Sigma](queries/sigma/hl-0011_oauth_consent_abuse.yml) · [KQL](queries/kql/hl-0011_oauth_consent_abuse.kql) · [SPL](queries/spl/hl-0011_oauth_consent_abuse.spl) |
| [HL-0012](playbooks/HL-0012-T1621-mfa-fatigue.md) | MFA fatigue / push bombing (Entra ID) | T1621, T1078.004 | Beginner | [Sigma](queries/sigma/hl-0012_mfa_fatigue.yml) · [KQL](queries/kql/hl-0012_mfa_fatigue.kql) · [SPL](queries/spl/hl-0012_mfa_fatigue.spl) |
| [HL-0013](playbooks/HL-0013-T1053.003-T1543.002-linux-cron-systemd-persistence.md) | Linux cron and systemd persistence | T1053.003, T1543.002 | Intermediate | [Sigma](queries/sigma/hl-0013_linux_cron_systemd_persistence.yml) · [KQL](queries/kql/hl-0013_linux_cron_systemd_persistence.kql) · [SPL](queries/spl/hl-0013_linux_cron_systemd_persistence.spl) |
| [HL-0014](playbooks/HL-0014-T1071.004-dns-c2-beaconing.md) | DNS C2 beaconing and tunneling | T1071.004, T1572 | Advanced | [Sigma](queries/sigma/hl-0014_dns_c2_beaconing.yml) · [KQL](queries/kql/hl-0014_dns_c2_beaconing.kql) · [SPL](queries/spl/hl-0014_dns_c2_beaconing.spl) |

ATT&CK tactic names follow ATT&CK v19 and later, where *Defense Evasion* is split into **Stealth** and **Defense Impairment**. The Navigator layer targets the current release (see [`navigator/COVERAGE.md`](navigator/COVERAGE.md)).

## Quick start

1. **Clone the repo**
   ```bash
   git clone https://github.com/NexusSecurityAdvisors/cti-hunt-loop-kit.git
   cd cti-hunt-loop-kit
   ```
2. **Pick a priority intelligence requirement (PIR)** using `templates/pir-worksheet.md`.
3. **Write a hypothesis card** (see [playbooks/](playbooks/) for a worked example) for one ATT&CK technique tied to that PIR.
4. **Run the matching query** from `queries/` against your platform, or practice first on the synthetic lab in [`data/`](data/README.md).
5. **Record the outcome** in `templates/hunt-report.md`, then complete `templates/intel-feedback.md` so the loop closes.

## Practice lab and workshop

The [`workshop/`](workshop/README.md) folder contains a 3.5-hour, hands-on lab built on a fictional ransomware intrusion, *Operation Quiet Ledger*. The intrusion starts with an MFA-fatigued Entra ID account and ends with encrypted Windows and Linux servers. The intrusion is hidden in five days of synthetic telemetry ([`data/`](data/README.md)), and benign look-alikes are planted for every hunt. You can run it in KQL (free Azure Data Explorer cluster), SPL (Splunk trial) or Sigma + Python with no SIEM at all.

```bash
python -m venv .venv && source .venv/bin/activate   # Python 3.14 (see .python-version)
pip install -r requirements.txt
python tests/test_lab_detections.py   # every Sigma rule vs. the lab answer key
```

<p align="center"><img src="assets/demo-lab-tests.gif" alt="Terminal recording: all 14 Sigma rules pass against the lab answer key, then the repository consistency check passes" width="85%"></p>

How a rule is tested, end to end:

```mermaid
flowchart LR
    G[generate_lab_data.py<br/>fixed seed] --> D[(Lab telemetry<br/>JSONL + CSV)]
    G --> K[answer_key.json<br/>malicious + look-alikes]
    S[Sigma rule] -->|pySigma SQLite backend| Q[SQL]
    D --> DB[(In-memory SQLite)]
    Q --> DB
    DB --> H[Hits by LabEventId]
    H --> C{Exactly matches<br/>answer key?}
    K --> C
    C -->|yes| P[PASS]
    C -->|no| F[FAIL with missed /<br/>unexpected events]
```

## Security and automation (DevSecOps)

Every change is validated, scanned and, on release, shipped with an SBOM and signed provenance. Scheduled jobs keep content current and open reminder issues instead of relying on memory.

```mermaid
flowchart TB
    subgraph PR["Every push and pull request"]
        direction LR
        V[Validate<br/>rules · lab · consistency] --> CQ[CodeQL<br/>Python + Actions] --> DR[Dependency<br/>review] --> Z[zizmor<br/>workflow audit]
    end
    subgraph SCHED["On a schedule"]
        direction LR
        W[Weekly maintenance<br/>links · source age · ATT&CK] --> QR[Quarterly<br/>content review] --> SC[OpenSSF<br/>Scorecard] --> DB[Dependabot<br/>Actions + pip]
    end
    subgraph REL["Tag v*.*.*"]
        direction LR
        R1[Re-validate] --> R2[Zip + CycloneDX SBOM] --> R3[SLSA provenance<br/>attestation] --> R4[GitHub release]
    end
    PR --> CS[(Code scanning alerts)]
    SCHED --> I[(Self-closing tracking issues)]
    PR -. merge to main .-> REL
```

| Workflow | Runs | What it does |
|---|---|---|
| [Validate](.github/workflows/validate.yml) | push, PR | `sigma check`, Splunk conversion, lab reproducibility, every rule vs. the answer key, repo consistency, metrics, Navigator layer and bibliography up to date |
| [CodeQL](.github/workflows/codeql.yml) | push, PR, weekly | `security-extended` analysis of the Python tooling and of the workflows |
| [Dependency review](.github/workflows/dependency-review.yml) | PR | Blocks new dependencies with known vulnerabilities (moderate+) or disallowed licenses |
| [Workflow security](.github/workflows/workflow-security.yml) | `.github/` changes, weekly | [zizmor](https://docs.zizmor.sh/) audit of every workflow, results in code scanning |
| [OpenSSF Scorecard](.github/workflows/scorecard.yml) | push, weekly | Supply-chain posture score (badge above) |
| [Scheduled maintenance](.github/workflows/maintenance.yml) | weekly, quarterly | Broken links, sources older than 4 years, new ATT&CK release → one self-closing tracking issue; quarterly content-review checklist issue |
| [Release](.github/workflows/release.yml) | tag `v*.*.*` | Re-validates, packages the kit, builds a CycloneDX SBOM, signs build provenance, publishes the release |
| [Dependabot](.github/dependabot.yml) | weekly | Grouped updates for SHA-pinned Actions and pinned Sigma tooling |

All workflows start from `permissions: {}`, grant each job only what it needs, pin third-party actions to full commit SHAs and never persist the checkout token. Run the same checks locally with [`pre-commit`](.pre-commit-config.yaml) (includes [gitleaks](https://github.com/gitleaks/gitleaks) secret scanning):

```bash
pip install -r requirements.txt pre-commit && pre-commit install
pre-commit run --all-files
```

**Verify a release** before using it in a workshop:

```bash
gh attestation verify cti-hunt-loop-kit-v1.3.0.zip -R NexusSecurityAdvisors/cti-hunt-loop-kit
sha256sum -c SHA256SUMS
```

CI, tests and the workshop all use the Python version in [`.python-version`](.python-version) (3.14). Python 3.15 is not used yet because pySigma's `google-re2` dependency has no 3.15 wheels; bump `.python-version` once it does.

## Hunt hypothesis card (preview)

```markdown
## Hypothesis ID: HL-0001
- Intel source / PIR:
- Adversary / campaign:
- ATT&CK technique(s): e.g., T1059.001 PowerShell
- Hypothesis: "If <adversary> is active in our environment, we expect to see <observable> in <data source>."
- Data sources required:
- Query reference: queries/<platform>/<file>
- Time window:
- Expected benign activity (known noise):
- Outcome: [ ] Confirmed  [ ] Refuted  [ ] Inconclusive (data gap)
- Follow-on: [ ] New detection  [ ] Intel update  [ ] Data-source gap ticket
```

## Measuring the loop

Suggested hunt program metrics. Track them in [`metrics/hunt-tracker.csv`](metrics/hunt-tracker.csv) and compute them with `python metrics/hunt_metrics.py`:

- Hunts completed per PIR
- Hypotheses confirmed / refuted / inconclusive
- Detections created from hunts
- Mean time from intel receipt to first hunt
- Data-source gaps identified and closed
- Intel products updated from hunt findings

## Roadmap

- [x] Core templates (PIR, hypothesis card, hunt report, intel feedback)
- [x] First playbook: HL-0001 encoded PowerShell and download cradles (Sigma, KQL, SPL)
- [x] Nine more ATT&CK-mapped playbooks (HL-0002 to HL-0010) with Sigma, KQL and SPL
- [x] Synthetic lab dataset and workshop exercises ([`data/`](data/README.md), [`workshop/`](workshop/README.md))
- [x] Hunt metrics tracker ([`metrics/`](metrics/README.md))
- [x] CI: every Sigma rule is tested against the lab dataset
- [x] Cloud identity hunts (OAuth consent abuse, MFA fatigue), Linux persistence and DNS C2 beaconing (HL-0011 to HL-0014), added to the lab and workshop
- [x] ATT&CK Navigator layer for kit coverage ([`navigator/`](navigator/COVERAGE.md)), regenerated and checked in CI
- [x] CI hardening: SHA-pinned actions, pinned Python tooling, Dependabot, lab reproducibility and repo consistency checks (v1.2, see [`CHANGELOG.md`](CHANGELOG.md))
- [x] Research bibliography with automated freshness checks, CodeQL, Scorecard, zizmor, signed releases with SBOM, scheduled maintenance issues, animated banner and demo (v1.3)
- [x] 65-second explainer video ([`assets/hunt-loop-explainer.mp4`](assets/hunt-loop-explainer.mp4), reproducible from [`tools/explainer/`](tools/explainer/))

## Contributing

Contributions are welcome: new playbooks, query translations, and lessons learned from running the loop in real programs.

1. Fork the repo and create a feature branch.
2. Follow the existing templates and include ATT&CK technique IDs.
3. **Never commit real customer data, IOCs under restrictive TLP, or proprietary telemetry.** Use synthetic or publicly shareable (TLP:CLEAR) material only.
4. If you add a playbook, add matching malicious and benign events to `data/generate_lab_data.py`, then regenerate so `tests/test_lab_detections.py` covers your rule. Add a row to the playbook table above and run `python tools/build_navigator_layer.py` to refresh the coverage layer.
5. Run the checks under [Security and automation](#security-and-automation-devsecops) locally (`pre-commit run --all-files`). Cite new sources in [`docs/references.yml`](docs/references.yml).
6. Open a pull request describing what you added and how you tested it.

## Disclaimer

This kit is provided for educational and defensive purposes. Test all queries in a non-production environment and tune them for your telemetry before operational use.

## Citing

If you use the kit in research or teaching, cite it with the metadata in [`CITATION.cff`](CITATION.cff) (GitHub's *Cite this repository* button generates APA and BibTeX).

## License

Code and content are released under the [Apache License 2.0](LICENSE).

## Author

**Dan Sorensen** — Nexus Security Advisors · OWASP AI Exchange core team · Forbes Technology Council contributor
Co-author, *Advanced Cyber Threat Intelligence and Hunting* (with Gianluca Tiepolo)
