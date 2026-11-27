# Preflight Checklist

Run this with the telemetry owner before the first query. A hunt that fails preflight can still run, but a clean result can only be recorded as **Inconclusive**, never as a bounded non-observation.

| # | Check | Pass / Fail | Evidence |
| --- | --- | --- | --- |
| 1 | Every data source the card needs exists and is reachable | | |
| 2 | Retention covers the full hunt window (earliest record on or before the window start) | | |
| 3 | The time window is written on the card | | |
| 4 | The query logic has been tested on known-good data, or on a known-positive sample | | |
| 5 | Scope (hosts, tenants, sites, accounts) is written down and matches the data's coverage | | |
| 6 | Field names and time zones are confirmed (UTC versus local) | | |
| 7 | Known gaps are listed (sensors down, log rollovers, unparsed sources) | | |

**Telemetry owner sign-off:** name, date

**Result:** Pass / Fail. If Fail, raise a collection requirement now, not after the hunt.
