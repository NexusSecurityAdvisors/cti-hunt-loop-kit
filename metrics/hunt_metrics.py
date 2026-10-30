#!/usr/bin/env python3
"""Compute Hunt Loop program KPIs from metrics/hunt-tracker.csv (stdlib only).

    python metrics/hunt_metrics.py [path/to/hunt-tracker.csv]
"""
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import median

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("hunt-tracker.csv")
rows = list(csv.DictReader(path.open(newline="")))
if not rows:
    sys.exit("No hunts recorded yet.")


def ts(v):
    return datetime.strptime(v.strip(), "%Y-%m-%dT%H:%MZ") if v and v.strip() else None


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


n = len(rows)
outcomes = Counter(r["outcome"].strip().lower() for r in rows)
per_pir = defaultdict(int)
for r in rows:
    per_pir[r["pir_id"] or "(none)"] += 1
lead = [(ts(r["hunt_started_utc"]) - ts(r["intel_received_utc"])).total_seconds() / 3600
        for r in rows if ts(r["hunt_started_utc"]) and ts(r["intel_received_utc"])]
dets = sum(r["detection_created"].strip().lower() == "yes" for r in rows)
gaps_found = sum(num(r["data_gaps_found"]) for r in rows)
gaps_closed = sum(num(r["data_gaps_closed"]) for r in rows)
intel = sum(num(r["intel_updates"]) for r in rows)
hours = sum(num(r["hours_spent"]) for r in rows)
mal = sum(num(r["malicious_clusters"]) for r in rows)
ben = sum(num(r["benign_clusters"]) for r in rows)
techniques = {t for r in rows for t in r["attack_techniques"].split(";") if t}

print(f"Hunt Loop metrics - {path.name} ({n} hunts)\n")
print(f"Hunts per PIR ................ " + ", ".join(f"{k}: {v}" for k, v in sorted(per_pir.items())))
print(f"Outcomes ..................... " + ", ".join(f"{k}: {v} ({v / n:.0%})" for k, v in outcomes.most_common()))
if lead:
    print(f"Intel-to-first-hunt (hours) .. median {median(lead):.1f}, max {max(lead):.1f}")
print(f"Detections created ........... {dets} ({dets / n:.0%} of hunts)")
print(f"Data-source gaps ............. {gaps_found:g} found, {gaps_closed:g} closed")
print(f"Intel products updated ....... {intel:g}")
print(f"ATT&CK techniques covered .... {len(techniques)}")
print(f"Triage ratio (benign:malicious clusters) {ben:g}:{mal:g}")
print(f"Effort ....................... {hours:.1f} h total, {hours / n:.1f} h per hunt")
