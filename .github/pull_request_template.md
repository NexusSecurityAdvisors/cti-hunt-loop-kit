## What does this change?

<!-- New playbook, query translation, template update, fix, docs -->

## ATT&CK technique(s)

<!-- e.g., T1059.001 -->

## How was it tested?

<!-- Platform and data used (lab, synthetic, public dataset). Never production data in the PR. -->

## Checklist

- [ ] Content is **TLP:CLEAR**: no customer data, internal hostnames, real credentials, or restricted IOCs
- [ ] Follows the existing templates and naming (`HL-####`)
- [ ] Sigma rules pass `sigma check` (the Validate workflow runs this automatically)
- [ ] New or changed rules have malicious and benign lab events, and `python tests/test_lab_detections.py` passes
- [ ] `python tests/test_repo_consistency.py` and `python tools/build_navigator_layer.py --check` pass
- [ ] Known benign sources and false positives are documented
