# Hypothesis Card

Fill in one card per hypothesis before any query is written. The disproof condition is written first, on purpose: it is a check on confirmation bias.

| Field | Entry |
| --- | --- |
| Card ID | HC-____ |
| PIR reference | PIR-__ : |
| Decision owner (from the PIR) | |
| Source intelligence | Title, publisher, date |
| Source grade (Admiralty) | Reliability A to F / Credibility 1 to 6, e.g. B2 |
| Hypothesis | If [adversary or behavior] is present in [scope], we expect to see [observable] in [data source]. |
| ATT&CK technique(s) and version | e.g. T1528, T1098.001 (ATT&CK v20.0) |
| Expected observables | Exact events, fields, and values |
| Data required | |
| Data available | List separately from "required" so gaps are visible |
| Scope | Tenants, hosts, sites, accounts in scope |
| Time window | From YYYY-MM-DD to YYYY-MM-DD |
| Disproof condition | What a clean result looks like, and the confidence it supports in ICD 203 terms (e.g. "unlikely") |
| Time box | Analyst hours before the hunt closes or escalates |
| Hunter / CTI analyst | |
| Preflight result | Pass / Fail (attach checklist) |
| Outcome | Supported finding / Escalated incident / Bounded non-observation / Inconclusive |
| Follow-on | Detection ID, incident ID, or collection requirement ID |

## Worked example

| Field | Entry |
| --- | --- |
| PIR reference | PIR-03: cloud identity targeting |
| Source grade | B2 (usually reliable, probably true) |
| Hypothesis | If an actor holds a stolen or consented OAuth token, we expect user consents to unverified apps requesting mail or file scopes, or credentials added to existing service principals, outside change windows and without a ticket, in the identity provider audit log. |
| ATT&CK (v20.0) | T1528 Steal Application Access Token; T1098.001 Account Manipulation: Additional Cloud Credentials |
| Time window | 30 days |
| Disproof condition | No such events across the full window with audit retention confirmed: it is "unlikely" this path was used in the window |
| Time box | 8 analyst hours |
