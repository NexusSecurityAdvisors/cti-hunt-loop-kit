# Workshop lab guide: Closing the Hunt Loop

**Format:** hands-on, 3.5 hours (it also fits in two 90-minute blocks) · **Level:** intermediate SOC, CTI and DFIR practitioners · **Seats:** 20–40

You join the threat hunting team at Northwind Labs, a fictional company. An industry ISAC alert says a ransomware affiliate is targeting your sector. It gets in through macro documents, moves laterally with harvested service-account credentials, and exfiltrates to MEGA before encrypting. Your job is to run the Hunt Loop against five days of telemetry and decide whether that affiliate has already been inside. You also need to leave the program better than you found it.

## Learning objectives

By the end of the lab, participants can:

1. Turn an intelligence report into PIRs and testable hunt hypotheses.
2. Run ATT&CK-mapped hunts in Sigma, KQL or SPL and **triage** results, telling malicious activity apart from benign look-alikes.
3. Pivot from one finding to reconstruct an intrusion timeline.
4. Close the loop: promote a detection, record data gaps and send structured feedback to the intel team.
5. Measure the hunt program with outcome-based metrics.

## Before you arrive

Choose **one** of these platform tracks. All three use the same dataset ([`data/`](../data/)).

| Track | What you need | Queries |
|---|---|---|
| KQL | Free Azure Data Explorer cluster with the lab CSVs ingested ([instructions](../data/README.md#loading-the-data)) | `queries/kql/` |
| SPL | Splunk trial / dev license with the lab JSONL uploaded | `queries/spl/` |
| Sigma + Python | Python 3.9+, `pip install pysigma-backend-sqlite`, a notebook or a SQLite browser | `queries/sigma/` |

Also bring a copy of the templates in [`templates/`](../templates/). One copy per team is enough. Markdown, paper or a shared doc all work.

## Agenda

| Time | Module | Output |
|---|---|---|
| 0:00 | **0. Briefing.** The Hunt Loop, the scenario, lab setup check | Everyone can query the data |
| 0:20 | **1. Collect & prioritize.** Read the intel brief, write PIRs ([Exercise 1](exercises.md#exercise-1--from-intel-to-pirs)) | PIR worksheet |
| 0:40 | **2. Hypothesize.** Pick hunts, write hypothesis cards ([Exercise 2](exercises.md#exercise-2--hypothesis-cards)) | 2–3 hypothesis cards per team |
| 1:00 | **3–4. Hunt & triage, round 1.** Initial access and persistence: HL-0001, HL-0008, HL-0004, HL-0003 ([Exercise 3](exercises.md#exercise-3--hunt-round-1-initial-access-and-persistence)) | Findings with a verdict for each cluster |
| 1:45 | Break | |
| 1:55 | **3–4. Hunt & triage, round 2.** Credentials and lateral movement: HL-0006, HL-0002, HL-0005, HL-0009 ([Exercise 4](exercises.md#exercise-4--hunt-round-2-credentials-and-lateral-movement)) | Findings and a draft timeline |
| 2:35 | **3–4. Hunt & triage, round 3.** Exfiltration and impact: HL-0010, HL-0007, find the encryptor ([Exercise 5](exercises.md#exercise-5--hunt-round-3-exfiltration-and-impact)) | Complete timeline |
| 3:00 | **5–6. Operationalize & feed back** ([Exercise 6](exercises.md#exercise-6--close-the-loop)) | Hunt report, intel feedback, metrics row |
| 3:20 | Debrief. Walk through the timeline, discuss the look-alikes, compare metrics across teams | |

Facilitators: see [`facilitator-guide.md`](facilitator-guide.md). Do not hand it out before the debrief.

## Ground rules

- **Every hit gets a verdict:** malicious, suspicious or benign, each with a reason. "The query returned it" is not a reason.
- **Benign is a finding.** Write it down so it becomes a scoped exclusion, not a blind spot.
- **A missing data source is a finding too.** Record it as *Inconclusive (data gap)*. Do not record it as *Refuted*.
- Work in pairs or threes. Rotate who drives the keyboard each round.
