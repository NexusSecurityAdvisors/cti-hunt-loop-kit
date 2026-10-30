# Workshop exercises

Run these with the [lab guide](README.md). The time range for every query is the whole lab window, **2026-10-05 to 2026-10-09 UTC**. Set `lookback = 3650d` (KQL) or `earliest=0` (SPL).

---

## Intel brief (handout)

> **TLP:CLEAR · Sector ISAC Flash · fictional, for training**
>
> **Subject:** Ransomware affiliate "QUIET LEDGER" targeting manufacturing and engineering firms
>
> In the last 60 days, member organizations reported intrusions by an affiliate that deploys a ransomware locker after exfiltrating finance data. Observed tradecraft:
>
> - **Account takeover:** passwords from earlier phishing, then **MFA push bombing** late in the evening. Once in, the actor grants an **OAuth app** mailbox and file access and uses real email threads to make the next lure believable.
> - **Initial access:** macro-enabled Word documents themed as remittance or invoice notices. Some campaigns use HTA links instead.
> - **Execution:** hidden, encoded PowerShell download cradles. regsvr32 is used to load remote scriptlets.
> - **Persistence:** Run keys and scheduled tasks named to look like OneDrive or Windows Update. Payloads are staged in `C:\ProgramData\<random>\`.
> - **Credential access:** Kerberoasting shortly after initial access. LSASS is dumped with comsvcs.dll and with a renamed ProcDump.
> - **Lateral movement:** WMI (impacket-style), PsExec and RDP, using cracked **service accounts**.
> - **Command and control:** a custom implant that beacons over **DNS TXT** queries with encoded subdomains.
> - **Exfiltration:** renamed rclone to MEGA, usually overnight.
> - **Impact:** shadow copies deleted, Windows recovery disabled, backup catalog deleted. **Linux NAS and backup appliances** are encrypted too, after cron or systemd persistence is planted. Encryption follows within minutes.
>
> Infrastructure seen (rotates often, low confidence): `203.0.113.45`, `203.0.113.80`, `203.0.113.99` (VPN exit used for M365 sign-ins), `*.mega.co.nz`.
> Dwell time from initial access to encryption: **under 24 hours** in 3 of 4 reported cases.

---

## Exercise 1: From intel to PIRs

*Template: [`templates/pir-worksheet.md`](../templates/pir-worksheet.md) · 20 min*

1. Read the brief and write **two or three PIRs** that matter to Northwind Labs. Northwind is an engineering firm with a finance department and a single file server holding finance data.
2. For each PIR, list the ATT&CK techniques from the brief and the playbook (`HL-0001` … `HL-0010`) that tests it.
3. Rank the techniques. With only 90 minutes of hunting time, where do you start, and why?

> **Discussion:** IOCs (the IPs) versus behaviors (the TTPs). Which survives the infrastructure rotation the brief warns about?

## Exercise 2: Hypothesis cards

*Template: [`templates/hypothesis-card.md`](../templates/hypothesis-card.md) · 20 min*

Write one hypothesis card for each hunt your team will run in round 1. Each card must have:

- A falsifiable hypothesis: "If QUIET LEDGER is active, we expect to see … in … during …".
- A **Refuted if** condition that includes telemetry coverage.
- Expected benign activity, written down **before** you run the query.

## Exercise 3: Hunt round 1, identity, initial access and persistence

*Playbooks: [HL-0012](../playbooks/HL-0012-T1621-mfa-fatigue.md), [HL-0011](../playbooks/HL-0011-T1528-oauth-consent-abuse.md), [HL-0001](../playbooks/HL-0001-T1059.001-encoded-powershell.md), [HL-0008](../playbooks/HL-0008-T1218-lolbin-proxy-execution.md), [HL-0004](../playbooks/HL-0004-T1547.001-registry-run-keys.md), [HL-0003](../playbooks/HL-0003-T1053.005-scheduled-task-persistence.md) · 45 min*

1. Start in the cloud. HL-0012: which user was push-bombed, from where, and did they eventually approve? Then HL-0011: what did the adversary do in the minutes after that approval? Explain why resetting the user's password would **not** have evicted them.
2. Run each endpoint query. Stack the results the way the playbook says to.
3. HL-0001: one cluster is very large. Decode a sample. What is it, and why should its *shape* (hosts, parent, account, schedule) make you relaxed about it?
4. Find the first malicious **endpoint** event in the dataset. Record the **host, user, time and parent process**.
5. From that host, pivot ±15 minutes across process, registry and network data. What else did the adversary do in the first ten minutes?
6. Persistence hunts: each one has a benign look-alike. Write the one-line triage reason that separates it from the malicious hit.

**Checkpoint question:** what was patient zero, which document opened the door, and how is that document connected to the cloud activity the night before?

## Exercise 4: Hunt round 2, credentials and lateral movement

*Playbooks: [HL-0006](../playbooks/HL-0006-T1558.003-kerberoasting.md), [HL-0002](../playbooks/HL-0002-T1003.001-lsass-credential-dumping.md), [HL-0005](../playbooks/HL-0005-T1047-T1021.002-wmi-psexec-lateral-movement.md), [HL-0009](../playbooks/HL-0009-T1021.001-rdp-lateral-movement.md) · 40 min*

1. HL-0006: stack RC4 ticket requests by requesting account and count distinct services. Two patterns appear. Which one is the attack, and what measurement shows it?
2. Which service account was the adversary most likely able to crack and use? Use evidence from later hunts to back up your answer.
3. HL-0002: the dumps happened on two different hosts. What changed in the tooling between them, and how does the query still catch the renamed binary?
4. HL-0005 / HL-0009: map **source → account → destination** for every lateral movement you can confirm. Which hits are legitimate administration, and how do you know?
5. Add everything to a running timeline.

## Exercise 5: Hunt round 3, C2, exfiltration and impact

*Playbooks: [HL-0014](../playbooks/HL-0014-T1071.004-dns-c2-beaconing.md), [HL-0010](../playbooks/HL-0010-T1567.002-exfiltration-to-cloud-storage.md), [HL-0013](../playbooks/HL-0013-T1053.003-T1543.002-linux-cron-systemd-persistence.md), [HL-0007](../playbooks/HL-0007-T1490-inhibit-system-recovery.md) · 25 min*

1. HL-0014: the Sigma pre-filter returns two populations of long DNS names. Use the beaconing statistics to tell them apart. What is the beacon interval, which process sends it, and when did it start relative to the persistence you found in round 1?
2. HL-0010: two rclone usage patterns exist. Separate them by remote name, config path, binary name and account.
3. How much network activity went to MEGA, from which host, and over how long?
4. HL-0007: list every recovery-inhibition command and the hosts it ran on. What is the common parent?
5. **No query in the kit matches the encryptors.** Find the Windows one by pivoting from the account, the hosts and the staging folder you already know. HL-0013 points you to a Linux host. What was planted there, and what ran after it?
6. Put the full timeline together, from the first MFA prompt to encryption. How long was dwell time? Compare it with the ISAC brief.

## Exercise 6: Close the loop

*Templates: [`hunt-report.md`](../templates/hunt-report.md), [`intel-feedback.md`](../templates/intel-feedback.md) · [metrics tracker](../metrics/) · 20 min*

1. **Operationalize:** choose the **two** Sigma rules you would promote first. Write the scoped exclusions each one needs, based on the benign look-alikes you found. Check them against the [promotion criteria](../detections/README.md).
2. **Data gaps:** which hunts would have been *Inconclusive* with less telemetry? Name at least one data source the lab did not have that would have helped. For example, HL-0003 has no 4698 events and HL-0005 has no 7045 events.
3. **Intel feedback:** fill in `intel-feedback.md` for the ISAC. Include new or confirmed TTPs, IOCs with your confidence in each, and anything in the brief your hunt contradicted.
4. **Metrics:** add one row per hunt to `metrics/hunt-tracker.csv`, then run `python metrics/hunt_metrics.py`. Which KPI would your CISO care most about?
