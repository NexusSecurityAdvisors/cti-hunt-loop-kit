# From PIR to Proof: A Hands-On Intelligence-Driven Hunting Lab

Half-day workshop (4 hours including a 20-minute break). Teams of three.

You are the CTI and hunt team at **Halvard Aerostructures**, a fictional mid-sized aerospace supplier with a cloud identity tenant and an OT engineering network reached by vendors through a jump host. Leadership wants to know whether adversaries are reaching engineering data. A fictional intelligence report has just landed.

## What you need

- A laptop with a spreadsheet application
- Optional: Python 3 with pandas
- The `lab/` folder from this kit

## Agenda

| Time | Module | You will produce |
| --- | --- | --- |
| 0:00 to 0:15 | Welcome, loop overview, lab setup check | Data opens on every laptop |
| 0:15 to 0:55 | [M1: Writing PIRs a hunter can use](exercises/M1-pirs.md) | Two PIRs with decision owners |
| 0:55 to 1:45 | [M2: From report to hypothesis card](exercises/M2-hypothesis-cards.md) | Two hypothesis cards |
| 1:45 to 2:15 | [M3: Preflight and data reality check](exercises/M3-preflight.md) | Two preflight results |
| 2:15 to 2:35 | Break | |
| 2:35 to 3:25 | [M4: Run and record the hunt](exercises/M4-hunt.md) | Hunt log and outcome records |
| 3:25 to 3:50 | [M5: Outcomes, Sigma, and source scoring](exercises/M5-outcomes-scoring.md) | A Sigma rule and a source score |
| 3:50 to 4:00 | [M6: Board brief and take-home plan](exercises/M6-board-brief.md) | A one-page brief and your own first PIR |

## Lab files

| File | What it is |
| --- | --- |
| `lab/intel/fictional-report-copper-lantern.md` | The intelligence report (fictional) |
| `lab/data/data_inventory.csv` | What data exists, who owns it, how long it is kept |
| `lab/data/identity_audit.csv` | 30 days of identity provider audit events |
| `lab/data/change_calendar.csv` | Approved change windows and tickets |
| `lab/data/jumphost_sessions.csv` | OT jump host remote sessions |
| `lab/data/approved_vendors.csv` | Vendor accounts allowed to connect |

All data is synthetic. Times are UTC. The lab clock reads **2027-03-03 00:00 UTC**.
