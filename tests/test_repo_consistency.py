#!/usr/bin/env python3
"""
Repository consistency checks for the CTI Hunt Loop Kit (standard library plus PyYAML).

- Every playbook HL-#### has a Sigma, KQL and SPL query, an answer-key entry and a row in README.md.
- Every query file belongs to an existing playbook.
- Sigma rule IDs are valid, unique UUIDs, and each rule references its own playbook.
- Every relative link in the Markdown files points at a file or folder that exists.

    python tests/test_repo_consistency.py
"""
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
errors = []


def err(msg):
    errors.append(msg)


playbooks = {re.match(r"(HL-\d{4})", p.name).group(1): p for p in sorted((ROOT / "playbooks").glob("HL-*.md"))}
answer_key = json.loads((ROOT / "data" / "answer_key.json").read_text())["hunts"]
readme = (ROOT / "README.md").read_text()

# 1. Each playbook has its three queries, an answer-key entry and a README row
for hunt, path in playbooks.items():
    stem = hunt.lower()
    for folder, ext in (("sigma", "yml"), ("kql", "kql"), ("spl", "spl")):
        if not list((ROOT / "queries" / folder).glob(f"{stem}_*.{ext}")):
            err(f"{hunt}: no {folder.upper()} query in queries/{folder}/")
    if hunt not in answer_key:
        err(f"{hunt}: missing from data/answer_key.json")
    if f"[{hunt}](playbooks/{path.name})" not in readme:
        err(f"{hunt}: no playbook row in README.md")

# 2. No orphan query files
for q in (ROOT / "queries").rglob("hl-*.*"):
    hunt = "HL-" + re.match(r"hl-(\d{4})", q.name).group(1)
    if hunt not in playbooks:
        err(f"{q.relative_to(ROOT)}: no matching playbook {hunt}")

# 3. Sigma IDs and references
seen = {}
for rule_path in sorted((ROOT / "queries" / "sigma").glob("*.yml")):
    hunt = "HL-" + re.match(r"hl-(\d{4})", rule_path.name).group(1)
    for doc in yaml.safe_load_all(rule_path.read_text()):
        if not doc:
            continue
        rid = str(doc.get("id", ""))
        try:
            uuid.UUID(rid)
        except ValueError:
            err(f"{rule_path.name}: invalid or missing id '{rid}'")
        if rid in seen:
            err(f"{rule_path.name}: id {rid} also used in {seen[rid]}")
        seen[rid] = rule_path.name
        if "logsource" in doc and hunt in playbooks:
            if not any(playbooks[hunt].name in r for r in doc.get("references", [])):
                err(f"{rule_path.name}: references do not link to {playbooks[hunt].name}")

# 4. Relative Markdown links resolve
LINK = re.compile(r"\]\(([^)\s]+)\)")
for md in sorted(ROOT.rglob("*.md")):
    if ".git" in md.parts:
        continue
    text = re.sub(r"```.*?```", "", md.read_text(), flags=re.S)  # ignore code blocks
    for target in LINK.findall(text):
        if re.match(r"^(https?:|mailto:|#)", target):
            continue
        rel = target.split("#", 1)[0]
        if rel and not (md.parent / rel).resolve().exists():
            err(f"{md.relative_to(ROOT)}: broken link -> {target}")

for e in errors:
    print(f"FAIL {e}")
print(f"{'FAIL' if errors else 'PASS'}: {len(playbooks)} playbooks, {len(seen)} Sigma rules checked, {len(errors)} problem(s)")
sys.exit(1 if errors else 0)
