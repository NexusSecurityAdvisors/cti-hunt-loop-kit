# Hunt program metrics

A simple, git-friendly tracker for measuring the Hunt Loop by **outcomes, not activity**. Add one row to [`hunt-tracker.csv`](hunt-tracker.csv) for each completed hunt, then run:

```bash
python metrics/hunt_metrics.py            # or pass a path to your own CSV
```

The four `LAB-*` rows are worked examples from the workshop. Delete them when you start tracking real hunts. Keep the tracker TLP:CLEAR, or store it privately if it names internal hosts.

## Fields

| Column | Meaning |
|---|---|
| `hunt_id` | Your unique ID for this run of a hunt |
| `playbook` | `HL-####` playbook used, or `ad-hoc` |
| `pir_id` | The priority intelligence requirement it answers |
| `attack_techniques` | ATT&CK IDs separated by `;` |
| `intel_source` | Report, advisory or internal finding that triggered the hunt |
| `intel_received_utc` / `hunt_started_utc` / `hunt_completed_utc` | `YYYY-MM-DDTHH:MMZ` |
| `platform` | KQL, SPL, Sigma backend, EDR console … |
| `outcome` | `confirmed`, `refuted` or `inconclusive` (use `inconclusive` for data gaps; never `refuted`) |
| `malicious_clusters` / `benign_clusters` | Result clusters triaged as malicious vs. benign |
| `hosts_affected` | Hosts with confirmed malicious activity |
| `data_gaps_found` / `data_gaps_closed` | Telemetry gaps identified by this hunt / closed since |
| `detection_created` | `yes` if a rule was promoted to production |
| `detection_ref` | ID of that production rule |
| `intel_updates` | Intel products (reports, PIRs, IOC sets) updated from this hunt |
| `hours_spent` | Analyst effort |

## KPIs and what they tell leadership

| KPI | Why it matters |
|---|---|
| Hunts per PIR | Shows the program is driven by intel priorities, not by whatever is interesting |
| Outcome mix (confirmed / refuted / inconclusive) | A high *inconclusive* share means visibility debt. Report it as risk |
| Intel-to-first-hunt time | How quickly new threat intel turns into defensive action |
| Detections created per hunt | The automation dividend: each one means the same hunt never has to be done by hand again |
| Data gaps found vs. closed | Shows whether hunting is actually improving telemetry |
| Intel products updated | Proves the loop closes back to CTI |
| ATT&CK techniques covered | Coverage breadth across the threat model (pair with an ATT&CK Navigator layer) |
| Triage ratio | High benign volume shows where tuning or asset context is missing |
| Effort per hunt | Capacity planning and the ROI denominator |

Avoid "number of queries run" or "events reviewed". Those measure motion, not risk reduction.
