# Playbook HL-0007 — Inhibit System Recovery

| Field | Value |
|---|---|
| Hypothesis ID | HL-0007 |
| ATT&CK | **T1490** Inhibit System Recovery · related: **T1486** Data Encrypted for Impact, **T1047** Windows Management Instrumentation |
| Tactic(s) | Impact |
| Platforms | Windows servers and endpoints |
| Difficulty | Beginner — simple command-line patterns, but a hit demands an immediate response |
| Queries | [Sigma](../queries/sigma/hl-0007_inhibit_system_recovery.yml) · [KQL](../queries/kql/hl-0007_inhibit_system_recovery.kql) · [SPL](../queries/spl/hl-0007_inhibit_system_recovery.spl) |

---

## 1. Intelligence basis

Nearly every ransomware family, and the affiliates who deploy them, destroys local recovery options immediately before encryption so victims cannot roll back:

- `vssadmin delete shadows /all /quiet` or `vssadmin resize shadowstorage` (shrinking storage silently deletes shadows).
- `wmic shadowcopy delete`, or PowerShell `Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }`.
- `bcdedit /set {default} recoveryenabled No` and `bootstatuspolicy ignoreallfailures` to block Windows Recovery Environment.
- `wbadmin delete catalog -quiet` / `delete systemstatebackup` to wipe the Windows Backup catalog.

These commands usually come from a batch file or the encryptor itself, run across many hosts within minutes. This is **late-stage** activity: by the time it appears, the intruder already holds privileged access and the encryptor is typically minutes away. Cite the advisory that motivates the hunt in your hypothesis card.

## 2. Hypothesis

> If ransomware has been staged or deployed in our estate, we expect to see **`vssadmin`, `wmic`, PowerShell, `bcdedit`, or `wbadmin` deleting shadow copies, disabling recovery, or deleting backup catalogs**, typically **several of these in sequence from the same parent** and on **multiple hosts in the same short window**, in process telemetry during the last 14–30 days.

**Refuted if:** process-creation telemetry covers ≥ 90% of in-scope hosts for the window and every hit is attributed to documented backup software or a change-controlled admin action.

## 3. Data sources

| Source | Event / table | Key fields |
|---|---|---|
| Sysmon | Event ID 1 (Process Create) | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User` |
| Windows Security | Event ID 4688 (command-line auditing required) | `NewProcessName`, `CommandLine`, `ParentProcessName` |
| Microsoft Defender XDR | `DeviceProcessEvents` | `FileName`, `ProcessCommandLine`, `InitiatingProcessCommandLine`, `AccountName` |
| Windows Application / System (pivot) | VSS events (e.g. source `VSS`), System 7036 service state | shadow storage changes, VSS service stopped |

**Pre-check:** confirm process telemetry covers **backup and file servers** — they are the highest-value targets for this technique and often the least instrumented. Without command lines (4688 only), log the outcome as **Inconclusive (data gap)**.

## 4. Hunt steps

Run this hunt in two modes.

**Retro-hunt (looking back over the window):**

1. **Run the query** for your platform across the hunt window.
2. **Stack by parent command line and account.** Ransomware shows several distinct recovery-inhibition actions from one parent in a few minutes; backup software shows one action, nightly, from its own service.
3. **Read the scope of each command.** `/all`, `recoveryenabled No`, and catalog deletion are destructive; `/oldest` on a single backup volume is housekeeping (both may carry `/quiet`).
4. **Pivot to the parent.** Pull the parent's command line and find the script or binary (`*.bat`, `*.ps1`, an unsigned EXE in `C:\ProgramData` or `C:\Users\Public`). Recover it from the host or EDR for analysis.
5. **Pivot to other hosts.** Search for the **same parent command line** on every host in the same window — affiliates push the same script to many servers at once. Then list everything that ran on each affected host **under the same account in the following minutes**, especially from the script's folder: the encryptor is usually there, and it may be launched by a different `cmd.exe` instance than the one running the script.
6. **Walk backward.** How did the script get there? Check PsExec / WMI execution (HL-0005), RDP logons (HL-0009), and the account used.

**Live hit (activity in the last hour): treat as an IR trigger, not a hunt lead.**

1. Escalate immediately under the incident response plan; do not wait for full triage.
2. Isolate affected hosts through EDR, and disable the executing account.
3. Use the parent-command-line pivot (step 5) to find every host running the same script and contain them too.
4. Protect backups: confirm offline/immutable copies are intact and cut the backup server's network access if it is affected.
5. Preserve evidence (memory, the script, the encryptor binary) before reimaging.

## 5. Known benign sources (tune, don't ignore)

| Source | How to recognize |
|---|---|
| Backup software pruning its own shadows | Backup service parent (e.g. Veeam, Commvault), `/oldest` or a single volume, SYSTEM, fixed nightly time |
| Admins reclaiming disk space | Named admin account, single host, single command, change ticket |
| OS imaging / build sequences | MDT/SCCM task sequence parent, during provisioning only |
| Recovery testing | Scheduled DR test, documented window |

Scope exclusions to **parent image + exact command line + host**. Never exclude `vssadmin.exe` or `bcdedit.exe` wholesale.

## 6. Triage questions

- How many distinct recovery-inhibition actions came from this parent, and over how many minutes?
- Is the parent a backup product's service, or `cmd.exe` running a batch file from a staging folder?
- Does the command target one volume and the oldest copy, or `/all`?
- Is the same parent command line present on other hosts in the same window?
- What did the parent run next? Is there an unknown binary writing to many files or shares?
- Which account ran it, and how did that account arrive on the host?

## 7. Operationalize

- Promote the Sigma rule at **high** severity with exclusions scoped to the backup service's exact parent and command line; consider an automated host-isolation response for `/all` or multi-action hits.
- Add a correlation rule: ≥ 2 distinct T1490 actions from the same parent within 10 minutes, or the same parent command line on ≥ 2 hosts.
- Keep **offline or immutable backups** and test restores; shadow copies are not a backup.
- Restrict who can run `vssadmin`, `wbadmin`, and `bcdedit` (application control) and enable EDR tamper and ransomware protection.
- Record outcome, detections, and data gaps in `templates/hunt-report.md` and `templates/intel-feedback.md`.

## Lab notes

- The lab covers five days of process telemetry. Expect a nightly backup look-alike that touches shadow copies — explain it from its parent, scope, and schedule.
- The malicious activity is not limited to one host. Stack by parent command line, not just by host.
- No hunt query matches the encryptor directly. Find it by pivoting on what the same account ran on the same hosts shortly after the recovery-inhibition commands; the script's folder is a strong clue.
- Work out how the parent script reached each host; one path is visible in another hunt's results, and one is not as obvious.

## References

Current threat intelligence and research (full list in [`docs/REFERENCES.md`](../docs/REFERENCES.md)):

- CISA, FBI, NSA, & MS-ISAC (2023). *#StopRansomware guide*. Cybersecurity and Infrastructure Security Agency. <https://www.cisa.gov/stopransomware/ransomware-guide> ([bib](../docs/REFERENCES.md#cisa-ransomware-guide))
- CISA & FBI (2024). *#StopRansomware: BlackSuit (Royal) ransomware (AA23-061A), updated August 2024*. Joint cybersecurity advisory. <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a> ([bib](../docs/REFERENCES.md#cisa-aa23-061a))

Technique and product documentation:

- MITRE ATT&CK T1490 — https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK T1486 — https://attack.mitre.org/techniques/T1486/
- CISA #StopRansomware advisories — https://www.cisa.gov/stopransomware
- SigmaHQ rule repository — https://github.com/SigmaHQ/sigma
