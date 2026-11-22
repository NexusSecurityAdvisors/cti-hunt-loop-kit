# CTI Hunt Loop Kit

Free, openly licensed templates, reference sheets, example detections, and a hands-on lab for running an intelligence-driven threat hunting program.

The kit accompanies the talk **Requirements to Hunts to Value: Building an Intelligence-Driven Threat Hunting Program** and the workshop **From PIR to Proof: A Hands-On Intelligence-Driven Hunting Lab**, both proposed for the FIRST Cyber Threat Intelligence Conference 2027 (Berlin). The method draws on the program-design chapters of *Advanced Cyber Threat Intelligence and Hunting* (Tiepolo & Sorensen, Packt, 2026).

Everything here is vendor-neutral. It runs on a spreadsheet; a threat intelligence platform or SIEM makes it faster but is not required.

## The loop

| Stage | Owner | Exit artifact | Kit files |
| --- | --- | --- | --- |
| 1. Requirement | CTI lead with the business owner | PIR naming the decision it informs, a decision owner, and a review date | [`templates/pir-register.csv`](templates/pir-register.csv) |
| 2. Hypothesis | CTI analyst and hunter | Hypothesis card | [`templates/hypothesis-card.md`](templates/hypothesis-card.md), [`reference/admiralty-scale.md`](reference/admiralty-scale.md), [`reference/icd203-likelihood.md`](reference/icd203-likelihood.md) |
| 3. Collection and hunt | Hunter with the telemetry owner | Preflight record and timestamped hunt log | [`templates/preflight-checklist.md`](templates/preflight-checklist.md), [`templates/collection-plan.csv`](templates/collection-plan.csv) |
| 4. Outcome | Hunter with detection engineering or DFIR | One of four qualified outcomes | [`templates/outcome-log.csv`](templates/outcome-log.csv), [`detections/sigma/`](detections/sigma/) |
| 5. Feedback | CTI lead | Updated PIRs, source scores, decision record | [`templates/product-value-rubric.md`](templates/product-value-rubric.md), [`templates/decision-log.csv`](templates/decision-log.csv), [`templates/metrics-scorecard.csv`](templates/metrics-scorecard.csv) |

### Four qualified outcomes

| Outcome | When it applies | Goes to |
| --- | --- | --- |
| Supported finding | Expected observable found and validated | Detection engineering, for a tested detection |
| Escalated incident | Evidence of active compromise | DFIR, with the hypothesis card attached |
| Bounded non-observation | Nothing found, and preflight confirmed the data could have shown it | Recorded with scope, window, and confidence |
| Inconclusive | Nothing found, but data was missing, too short, or untested | A collection or telemetry requirement; the PIR stays open |

A non-observation is never proof of absence. It holds only for the scope, time window, and data quality recorded.

## What is in the kit

```
templates/     PIR register, hypothesis card, preflight checklist, collection plan,
               outcome and decision logs, source-scoring rubric, metrics scorecard,
               RACI, 90-day rollout plan, board brief, vendor questions
reference/     Admiralty grading, ICD 203 likelihood terms, tool map, AI review gates,
               free resources, full reference list
detections/    Example Sigma rules from the lab (tune to your own log schema)
workshop/      Half-day lab: agenda, six exercises, fictional intelligence report,
               synthetic data and generator, facilitator guide and answer key
slides/        Talk and workshop decks (PowerPoint)
```

## Quick start

1. Copy `templates/pir-register.csv` and write three to five PIRs, each tied to a decision and an owner.
2. For one PIR, fill in `templates/hypothesis-card.md` from a report you already trust.
3. Run `templates/preflight-checklist.md` against your own data inventory before writing a query.
4. Record the result in `templates/outcome-log.csv` using one of the four outcomes.
5. After a month, score your sources with `templates/product-value-rubric.md` and fill in `templates/metrics-scorecard.csv`.

## Running the workshop lab

The lab needs only a spreadsheet. Python 3 with pandas is optional.

```bash
cd workshop/lab
python generate_lab_data.py      # regenerates data/ (deterministic, same output every time)
```

Participants start at [`workshop/README.md`](workshop/README.md). Facilitators use [`workshop/facilitator/`](workshop/facilitator/), which holds the answer key; remove that folder from any copy handed to participants before the session.

## Important notes

- **All lab data is synthetic.** Organizations, people, applications, and events are fictional. IP addresses come from the RFC 5737 documentation ranges, and domains use the reserved `.example` TLD.
- **The intelligence report in the lab is fictional** and written for training. It describes no real threat actor.
- **Detections are examples.** Field names differ between log pipelines; test any rule on known-good data before use.
- **Tool lists are examples, not endorsements.** Check current licensing before adopting any tool.
- **ATT&CK technique IDs** were checked against MITRE ATT&CK v20.0 (October 2026).
- This kit is an independent community resource. It is not produced or endorsed by FIRST, MITRE, or any vendor named.

## License

Templates, reference material, lab data, and documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Scripts: MIT. See [`LICENSE.md`](LICENSE.md).

## How to cite

See [`CITATION.cff`](CITATION.cff). Suggested: Sorensen, D. (2026). *CTI Hunt Loop Kit* (Version 1.0) [Computer software and templates].
