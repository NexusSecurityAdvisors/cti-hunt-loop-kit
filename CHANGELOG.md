# Changelog

All notable changes to the CTI Hunt Loop Kit. Dates are UTC.

## Unreleased

### Kit content
- Folded the *PIR to Proof* kit (previously a nested `cti-hunt-loop-kit/` copy) into the main layout, so there is one kit to maintain and check:
  - `workshop/pir-to-proof/`: half-day, spreadsheet-only lab (Halvard Aerostructures scenario, six exercises, deterministic lab data generator, fictional intel report).
  - `templates/`: PIR register, collection plan, preflight checklist, outcome and decision logs, product-value rubric, metrics scorecard, RACI, 90-day rollout, board brief, vendor questions, and `hypothesis-card-lite.md` (the lab's shorter card; the full card is unchanged).
  - `reference/`: Admiralty grading, ICD 203 likelihood terms, tool map, AI review gates, free resources, reference list.
  - `detections/sigma/`: the lab's two Entra ID example rules, now checked and test-converted in CI with the hunt queries.
  - `slides/`: talk and workshop decks.
- The PIR to Proof facilitator guide and answer key moved to the private facilitator repository, matching the Closing the Hunt Loop workshop.
- All material is now under Apache-2.0 (the nested copy was CC BY 4.0 for docs and MIT for scripts).

## v1.3.0 — 2026-10-31

### Research and documentation
- `docs/references.yml` → generated `docs/REFERENCES.md`: 18 sources (peer-reviewed, NIST, CISA joint advisories, vendor research), APA 7, all within ~4 years. Every playbook now cites current threat intelligence alongside the ATT&CK and product docs.
- README *Research basis* section; `CITATION.cff` for academic citation.
- 65-second explainer video embedded in the README (`assets/hunt-loop-explainer.mp4`; rendered deterministically from `tools/explainer/` with Playwright + ffmpeg).
- Animated SVG banner, terminal demo GIF recorded from the real test run (`tools/render_demo_gif.py`), Mermaid diagrams of the rule-testing flow and the DevSecOps pipeline.

### Security and automation
- New workflows: CodeQL (Python + Actions), OpenSSF Scorecard, dependency review, zizmor workflow audit, signed releases (CycloneDX SBOM + SLSA build provenance), scheduled maintenance (weekly links / source age / ATT&CK release; quarterly content-review issue).
- Every workflow starts from `permissions: {}` with per-job grants; all actions SHA-pinned; zizmor reports no findings.
- `CODEOWNERS`, `.pre-commit-config.yaml` (gitleaks, YAML/JSON checks, the kit's own tests).
- Validate also checks the bibliography and warns on sources older than 4 years.

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
- One Python version everywhere: `.python-version` (3.14) drives CI (`python-version-file`), and the README, workshop and data guides all reference it. 3.14 is the newest release the Sigma toolchain installs on (`google-re2` has no 3.15 wheels yet).
- Workshop and data guides install from `requirements.txt`.
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
