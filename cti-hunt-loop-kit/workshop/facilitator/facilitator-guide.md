# Facilitator Guide

**Remove this folder from any copy handed to participants.**

## Before the session

- [ ] Run `python lab/generate_lab_data.py` and `python facilitator/solve_lab.py`; confirm the output matches the answer key below.
- [ ] Put the participant copy of the kit (without `facilitator/`) on USB drives as a Wi-Fi fallback.
- [ ] Print one hypothesis card and one preflight checklist per team (optional).
- [ ] Brief the assistant on the answer key and the two traps (noise consents and the decoy credential rotation).

## Timing and facilitation notes

| Module | Watch for | Nudge |
| --- | --- | --- |
| M1 | PIRs written as topics ("monitor APTs") | "What decision would this change, and who makes it?" |
| M2 | Teams copying indicators into the hypothesis instead of behaviors | "Would your card still work if every IP changed tomorrow?" |
| M3 | Teams skipping the jump host retention check | "When is the earliest jump host record?" |
| M4 | Teams flagging all 14 low-risk user consents | "Which scopes and publishers did the report describe?" |
| M4 | Teams flagging the emergency-window rotation | "Check the change calendar for 2027-02-18." |
| M5 | Teams calling Hypothesis B a negative | "Could your data have shown activity on 2027-02-10?" |

## Answer key

### Preflight

| Source | Result | Why |
| --- | --- | --- |
| Identity provider audit log | Pass | Earliest record 2027-02-01; covers all 30 days |
| Change calendar | Pass | Covers the window |
| OT jump host session log | **Fail** | Earliest record 2027-02-24; covers 7 of 30 days; local only |

### Hypothesis A: supported finding

| Time (UTC) | Operation | Actor | Target | Detail |
| --- | --- | --- | --- | --- |
| 2027-02-06 03:12 | Consent to application | j.okafor | MailSync Pro | Unverified; Mail.Read, offline_access; IP 203.0.113.45; no ticket; Saturday night |
| 2027-02-09 22:47 | Consent to application | m.ruiz | DocView Connect | Unverified; Mail.Read, Files.Read.All; IP 198.51.100.23; no ticket |
| 2027-02-14 02:14 | Add service principal credentials | j.okafor | PLM Bridge | Sunday; no ticket; **same IP as the first consent** |

- Not findings: 14 user consents to verified apps with `User.Read` or `Calendars.Read` (noise), and the 2027-02-18 credential rotation by `cloud.ops` inside emergency window CW-E01 with ticket CHG-4199 (decoy).
- Confidence: "very likely" that the tenant was targeted as the report describes. Credential addition eight days after consent matches the report's timing.
- Follow-on: revoke both consents, remove the added credential, reset both users, deploy detections, and raise decision D-001 (restrict user consent).
- Good teams also note escalation: the credential addition to a trusted app is a reason to open an incident, not just ship a detection. Accept either "supported finding" or "escalated incident" if the team explains its reasoning.

### Hypothesis B: inconclusive

- 38 sessions, all from approved vendor accounts and allowed countries, 2027-02-24 to 2027-03-02.
- The hunt window starts 2027-02-01. 23 of 30 days have no data. Nothing found cannot be reported as a negative.
- Follow-on: collection requirement CR-001 (forward jump host logs to the SIEM with at least 90-day retention), decision D-002 for funding, PIR stays open.

### Source scoring

- As run: the report produced one supported finding (score 3) and one inconclusive result with a gap raised (score 2). Mean 2.5 across two products.
- If Hypothesis A had come back clean with full data: bounded non-observation (score 2). The report is still useful; it shaped visibility.

## Reference solution

`python facilitator/solve_lab.py` prints the preflight, both hunts, and the expected outcomes.
