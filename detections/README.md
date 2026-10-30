# Detections: promoting hunts to production

A hunt query is built for **recall**: it is broad, gets stacked, and is triaged by a person. A production detection must be built for **precision**: it fires on its own, so every alert has to be worth an analyst's time. This folder holds hunts that have crossed that line, along with the evidence for the decision.

## Promotion criteria

Promote a hunt query when **all** of the following are true:

1. **The hunt was run** over at least 14 days of representative telemetry, and the result is in a hunt report.
2. **Every benign cluster is explained** and turned into a **scoped exclusion**: parent image + signer + account + host group. Never exclude a whole binary such as `powershell.exe`.
3. **Expected volume is acceptable.** The tuned rule, replayed over the hunt window, yields fewer than about 1 alert per day per 10,000 endpoints, or whatever your SOC sets as its budget.
4. **It has been tested against a positive.** It fires on an atomic test, a red-team replay or the lab dataset (`tests/test_lab_detections.py`).
5. **It has a response.** A triage runbook exists, which can be the playbook's *Triage questions* section, and the alert is routed to an owner.
6. **Metadata is complete:** status moved from `experimental` to `test` (then `stable`), `level` reviewed, `falsepositives` updated, ATT&CK tags current, and the source `HL-####` referenced.

## Layout

```
detections/
└── <platform>/            # sigma/, sentinel/, splunk/, defender/ …
    └── HL-####_<name>.<ext>   # tuned rule with scoped exclusions
```

Keep the original hunt query in `queries/` unchanged. The production rule is a tuned descendant of it. When the rule is tuned again later, record why in the PR.

## Lab starting points

From the workshop dataset, these are the strongest candidates for promotion:

| Hunt | Why | Exclusions you will need |
|---|---|---|
| HL-0007 Inhibit recovery | High fidelity, almost no legitimate use of `/all`, `recoveryenabled no` or `delete catalog` | Backup agent parent with `/oldest` |
| HL-0002 LSASS dump | Very rare legitimately | Approved IR tooling, by signer and host group |
| HL-0006 Kerberoasting | Fires hours before impact | Fix RC4-only legacy accounts (move them to AES); exclude only while remediation is pending |
| HL-0008 LOLBin proxy execution | Remote scriptlets and HTAs are rarely legitimate | Named intranet HTA apps by full URL |
