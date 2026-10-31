# Changelog

All notable changes to the CTI Hunt Loop Kit. Dates are UTC.

## v1.2 — 2026-10-31

### Security and CI
- Pinned `actions/checkout` (v6.1.0) and `actions/setup-python` (v6.3.0) to full commit SHAs; both run on Node.js 24.
- Checkout no longer persists the job token (`persist-credentials: false`); jobs have time limits, superseded runs are cancelled.
- Runners pinned to `ubuntu-24.04` ahead of the `ubuntu-latest` move to Ubuntu 26.
- Added `requirements.txt` (pinned `sigma-cli`, SQLite and Splunk backends) and Dependabot for GitHub Actions and pip.
- New CI step: the lab dataset must match `data/generate_lab_data.py` output byte for byte.
- New `tests/test_repo_consistency.py`: playbook ↔ query ↔ answer key ↔ README agreement, unique Sigma IDs, no broken relative links.

### Documentation
- README: *Validation and CI* section, corrected ATT&CK version note (the Stealth / Defense Impairment split arrived in v19), updated layout and contributing steps.
- Workshop and data guides: Sigma + Python track needs Python 3.11+ (pySigma requirement) and installs from `requirements.txt`.
- Pull request checklist covers lab tests, consistency checks and the Navigator layer.
- Facilitator guide moved to a private repository so attendees cannot read ahead; available to facilitators on request.

## v1.1 — 2026-10

- Playbooks HL-0011 to HL-0014: OAuth consent abuse, MFA fatigue, Linux cron/systemd persistence, DNS C2 beaconing (Sigma, KQL, SPL).
- Lab data for Entra ID, Sentinel, Sysmon for Linux, Defender for Linux and DNS; workshop scenario extended.
- ATT&CK Navigator coverage layer and `navigator/COVERAGE.md`, checked in CI.

## v1.0 — 2026-10

- Core templates, playbooks HL-0001 to HL-0010 with Sigma, KQL and SPL.
- Synthetic lab dataset with answer key, workshop guide and exercises, hunt metrics tracker.
- CI runs every Sigma rule against the lab dataset.
