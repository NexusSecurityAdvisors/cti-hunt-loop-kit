# M4: Run and Record the Hunt (50 minutes)

**Goal:** run both hypotheses against the lab data and record each result in `templates/outcome-log.csv`.

## Hypothesis A: cloud identity

Suggested path (spreadsheet):

1. Open `identity_audit.csv`. Filter `operation` to `Consent to application` and `Add service principal credentials`.
2. For consents, look at `consent_type`, `publisher_verified`, and `permissions`. Which consents match the report's description?
3. Compare timestamps against `change_calendar.csv`. Which events fall outside every change window and have no `change_ticket`?
4. Pivot on `ip_address` and `actor`. Do any events connect to each other?

Python path: load the CSVs with pandas and express steps 1 to 4 as filters. Record your query logic in the hunt log so another analyst can repeat it.

## Hypothesis B: OT vendor access

1. Open `jumphost_sessions.csv` and `approved_vendors.csv`.
2. Look for sessions from accounts not on the approved list, or from countries other than the vendor's allowed country.
3. Note the earliest session in the file. Compare it with your preflight result from M3.

## Record

For each hypothesis, add a row to the outcome log: preflight result, outcome, scope, time window, confidence in ICD 203 terms, evidence summary, and follow-on.

## Watch for

- Noise: some user consents without tickets are normal. What separates them from the report's behavior?
- A decoy: one credential addition looks suspicious until you check the change calendar.
