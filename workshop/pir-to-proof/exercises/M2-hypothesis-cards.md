# M2: From Report to Hypothesis Card (50 minutes)

**Goal:** two hypothesis cards built from the COPPER LANTERN report, one for each PIR from M1.

## Tasks

1. (10 min) Read `lab/intel/fictional-report-copper-lantern.md`. Grade it on the Admiralty scale (`reference/admiralty-scale.md`). Grade the source and the key judgments separately.
2. (10 min) List the behaviors the report describes. Separate behaviors from indicators. Which would still be useful if every IP in the report changed tomorrow?
3. (25 min) Fill in one `templates/hypothesis-card-lite.md` for each PIR:
   - **Hypothesis A (cloud identity):** what should appear in the identity audit log?
   - **Hypothesis B (OT access):** what should appear in jump host sessions?
   - Write the **disproof condition first**, using ICD 203 terms (`reference/icd203-likelihood.md`).
4. (5 min) One team reads a card aloud; the room checks the ATT&CK IDs against v20.0.

## Hints

- The report says *when* activity happens and *what scopes* the apps request. Both belong in the expected observables.
- "Data required" and "data available" are separate rows on purpose. Leave "available" blank until M3.
