#!/usr/bin/env python3
"""
Render docs/REFERENCES.md from docs/references.yml and check source freshness.

    python tools/build_references.py            # write docs/REFERENCES.md
    python tools/build_references.py --check    # exit 1 if REFERENCES.md is stale or a cited id is unknown
    python tools/build_references.py --stale    # print sources older than the freshness window (exit 0)
    python tools/build_references.py --stale --as-issue   # same, as a Markdown issue body

Freshness: non-evergreen sources published more than MAX_AGE_YEARS ago are flagged so they can be
replaced or re-confirmed. CI reports them as warnings; the weekly maintenance workflow opens an issue.
Standard library plus PyYAML (installed with sigma-cli).
"""
import re
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "references.yml"
OUT = ROOT / "docs" / "REFERENCES.md"
MAX_AGE_YEARS = 4
TYPES = {"academic": "Peer-reviewed and academic", "standard": "Standards and frameworks",
         "government": "Government advisories and guidance", "industry": "Industry research"}


def load():
    refs = yaml.safe_load(SRC.read_text())
    ids = [r["id"] for r in refs]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        sys.exit(f"Duplicate reference ids: {', '.join(sorted(dupes))}")
    for r in refs:
        missing = {"id", "type", "authors", "title", "venue", "published", "url", "used_by"} - r.keys()
        if missing or r["type"] not in TYPES or not re.fullmatch(r"\d{4}-\d{2}", str(r["published"])):
            sys.exit(f"{r.get('id', '?')}: bad entry (missing {sorted(missing)} or bad type/published)")
    return refs


def age_years(published, today=None):
    today = today or date.today()
    y, m = map(int, str(published).split("-"))
    return (today.year - y) + (today.month - m) / 12


def stale(refs, today=None):
    return [r for r in refs if not r.get("evergreen") and age_years(r["published"], today) > MAX_AGE_YEARS]


def apa(r):
    year = str(r["published"])[:4]
    return f"{r['authors']} ({year}). *{r['title']}*. {r['venue']}. <{r['url']}>"


def playbook_link(u):
    if not u.startswith("HL-"):
        return "kit-wide"
    pb = next((ROOT / "playbooks").glob(f"{u}-*.md"), None)
    return f"[{u}](../playbooks/{pb.name})" if pb else u


def render(refs):
    lines = [
        "# References",
        "",
        "_Generated from [`references.yml`](references.yml) by `tools/build_references.py`. Do not edit by hand._",
        "",
        f"Citations use APA 7 style. Sources are kept to roughly the last {MAX_AGE_YEARS} years: CI and a weekly "
        "scheduled workflow flag any non-evergreen source that ages out, so it gets replaced or re-confirmed. "
        "Living resources (ATT&CK technique pages, vendor documentation, the Sigma specification) are linked "
        "from each playbook and treated as evergreen.",
        "",
    ]
    for t, heading in TYPES.items():
        group = sorted((r for r in refs if r["type"] == t), key=lambda r: (r["authors"], r["published"]))
        if not group:
            continue
        lines += [f"## {heading}", ""]
        for r in group:
            used = ", ".join(playbook_link(u) for u in r["used_by"])
            lines.append(f'- <a id="{r["id"]}"></a>{apa(r)}  ')
            lines.append(f"  `[{r['id']}]` · used by: {used}")
        lines.append("")
    lines += ["## How to add a source", "",
              "1. Add an entry to `docs/references.yml` (prefer peer-reviewed, government or standards bodies; "
              f"published within {MAX_AGE_YEARS} years).",
              "2. Cite it in the playbook's *References* section.",
              "3. Run `python tools/build_references.py` and commit both files.", ""]
    return "\n".join(lines)


def main():
    refs = load()
    md = render(refs)
    if "--stale" in sys.argv:
        old = stale(refs)
        if "--as-issue" in sys.argv:
            print(f"The following sources are older than {MAX_AGE_YEARS} years. Replace each with a newer "
                  "authoritative source, or re-confirm it and update `published` to the latest revision.\n")
            for r in old:
                print(f"- [ ] `{r['id']}` ({r['published']}): {r['title']} <{r['url']}>")
        else:
            for r in old:
                print(f"::warning file=docs/references.yml::{r['id']} published {r['published']} is older than "
                      f"{MAX_AGE_YEARS} years; replace or re-confirm")
            print(f"{len(old)} stale source(s) of {len(refs)}")
        return
    if "--check" in sys.argv:
        known = {r["id"] for r in refs}
        cited = set()
        for md_file in ROOT.rglob("*.md"):
            if ".git" not in md_file.parts:
                cited |= set(re.findall(r"REFERENCES\.md#([a-z0-9-]+)\)", md_file.read_text()))
        unknown = sorted(cited - known)
        if unknown:
            sys.exit(f"Unknown reference ids cited: {', '.join(unknown)}")
        if not OUT.exists() or OUT.read_text() != md:
            sys.exit("docs/REFERENCES.md is stale. Run python tools/build_references.py and commit the result.")
        print(f"References up to date ({len(refs)} sources, {len(cited)} cited by id).")
        return
    OUT.write_text(md)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
