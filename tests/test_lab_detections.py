#!/usr/bin/env python3
"""
Regression test: every Sigma rule in queries/sigma must return exactly the events the
answer key says it should (planted malicious events + documented benign look-alikes)
when run against the synthetic lab dataset in data/lab.

Rules are converted with the pySigma SQLite backend and executed in an in-memory database,
so this checks real rule logic, not just syntax.

    pip install "pysigma-backend-sqlite"
    python data/generate_lab_data.py   # optional: regenerate (deterministic)
    python tests/test_lab_detections.py
"""
import json
import re
import sqlite3
import sys
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "data" / "lab"
KEY = json.loads((ROOT / "data" / "answer_key.json").read_text())["hunts"]

SOURCES = {  # (product, category, service) -> lab file
    ("windows", "process_creation", None): LAB / "sysmon" / "process_creation.jsonl",
    ("windows", "registry_set", None): LAB / "sysmon" / "registry_set.jsonl",
    ("windows", "dns_query", None): LAB / "sysmon" / "dns_query.jsonl",
    ("windows", None, "security"): LAB / "security" / "security.jsonl",
    ("linux", "process_creation", None): LAB / "linux" / "process_creation.jsonl",
    ("azure", None, "signinlogs"): LAB / "entra" / "signinlogs.jsonl",
    ("azure", None, "auditlogs"): LAB / "entra" / "auditlogs.jsonl",
}


def load(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    cols = sorted({k for r in rows for k in r})
    db = sqlite3.connect(":memory:")
    db.create_function("REGEXP", 2, lambda pattern, value: value is not None and re.search(pattern, str(value)) is not None)
    # 'timestamp' is the column the pySigma SQLite backend uses for correlation windows
    db.execute(f"CREATE TABLE logs ([timestamp], {', '.join(f'[{c}]' for c in cols)})")
    db.executemany(f"INSERT INTO logs VALUES (?, {', '.join('?' * len(cols))})",
                   [[r["UtcTime"].rstrip("Z")] + [r.get(c) for c in cols] for r in rows])
    return db


def evidence_ids(db, row):
    """Map correlation evidence ('<n>:<rowid>') back to LabEventIds."""
    rowids = [int(e.split(":")[-1]) for e in json.loads(row["event_ids"])]
    return {db.execute("SELECT LabEventId FROM logs WHERE rowid = ?", (r,)).fetchone()[0] for r in rowids}


def main():
    backend = sqliteBackend()
    dbs = {}
    failures = 0
    for rule_path in sorted((ROOT / "queries" / "sigma").glob("hl-*.yml")):
        hunt = "HL-" + re.match(r"hl-(\d{4})", rule_path.name).group(1)
        collection = SigmaCollection.from_yaml(rule_path.read_text())
        rule = next(r for r in collection.rules if hasattr(r, "logsource"))
        ls = rule.logsource
        src = SOURCES[(ls.product, ls.category, ls.service)]
        db = dbs.setdefault(src, load(src))
        db.row_factory = sqlite3.Row
        mal = {e["id"] for e in KEY[hunt]["malicious"]}
        ben = {e["id"] for e in KEY[hunt]["benign_match"]}
        hits = set()
        for sql in backend.convert(collection):
            if sql.lstrip().upper().startswith("WITH"):  # correlation rule: must alert on malicious events only
                corr = set().union(*[evidence_ids(db, r) for r in db.execute(sql)] or [set()])
                ok = corr == mal
                failures += not ok
                print(f"{'PASS' if ok else 'FAIL'} {hunt} correlation: evidence {len(corr)} events "
                      f"({len(corr & mal)}/{len(mal)} malicious, {len(corr & ben)} benign)")
                continue
            hits |= {row[0] for row in db.execute(sql.replace("SELECT *", "SELECT LabEventId", 1))}
        expected = mal | ben
        missed, extra = expected - hits, hits - expected
        ok = not missed and not extra
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} {hunt} {rule_path.name}: {len(hits)} hits "
              f"({len(mal & hits)}/{len(mal)} malicious, {len(ben & hits)}/{len(ben)} benign look-alikes)")
        if missed:
            print(f"     missed: {sorted(missed)[:10]}")
        if extra:
            print(f"     unexpected: {sorted(extra)[:10]}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
