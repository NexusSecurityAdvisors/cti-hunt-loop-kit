#!/usr/bin/env python3
"""Generate the synthetic lab dataset for the PIR-to-Proof workshop.

Every organization, user, application, IP address, and event in this dataset
is fictional. IP addresses come from the documentation ranges reserved by
RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and the domain uses
the reserved .example TLD.

The output is deterministic: the same seed always produces the same files, so
facilitators and participants see identical data.

Usage:
    python generate_lab_data.py            # writes CSVs into ./data
    python generate_lab_data.py --out DIR  # writes CSVs into DIR

License: Apache-2.0 (see LICENSE at the repository root).
"""

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 2027
UTC = timezone.utc
DOMAIN = "halvard.example"

# Lab clock: the hunt is run "now", at the end of the 30-day window.
WINDOW_START = datetime(2027, 2, 1, 0, 0, tzinfo=UTC)
LAB_NOW = datetime(2027, 3, 3, 0, 0, tzinfo=UTC)
JUMPHOST_RETENTION_DAYS = 7  # the planted blind spot

USERS = [
    "a.lindqvist", "b.osei", "c.marchetti", "d.kowalski", "e.tanaka",
    "f.haddad", "g.oliveira", "h.brennan", "i.nwosu", "j.okafor",
    "k.dubois", "l.fischer", "m.ruiz", "n.petrov", "o.sato",
]
ADMINS = ["it.admin1", "it.admin2", "cloud.ops"]

KNOWN_APPS = [
    # name, app_id, publisher_verified, typical scopes
    ("PLM Bridge", "a1f0c3d2-0001", True, "Files.Read.All Sites.Read.All"),
    ("Expense Portal", "a1f0c3d2-0002", True, "User.Read"),
    ("Travel Booker", "a1f0c3d2-0003", True, "User.Read Calendars.Read"),
    ("Quality Records", "a1f0c3d2-0004", True, "Sites.ReadWrite.All"),
    ("Supplier Portal", "a1f0c3d2-0005", True, "User.Read profile"),
]

OPERATIONS_BENIGN = [
    "Update application",
    "Add member to role",
    "Reset user password",
    "Add user",
    "Update user",
]


def change_windows():
    """Weekly Tuesday 18:00-22:00 UTC windows plus one emergency window."""
    rows = []
    day = WINDOW_START - timedelta(days=7)
    n = 1
    while day < LAB_NOW + timedelta(days=7):
        if day.weekday() == 1:  # Tuesday
            start = day.replace(hour=18)
            rows.append({
                "window_id": f"CW-{n:03d}",
                "start_utc": start,
                "end_utc": start + timedelta(hours=4),
                "ticket": f"CHG-{4100 + n}",
                "description": "Standard weekly change window",
            })
            n += 1
        day += timedelta(days=1)
    emergency = datetime(2027, 2, 18, 13, 0, tzinfo=UTC)
    rows.append({
        "window_id": "CW-E01",
        "start_utc": emergency,
        "end_utc": emergency + timedelta(hours=2),
        "ticket": "CHG-4199",
        "description": "Emergency change: PLM Bridge certificate rotation",
    })
    return sorted(rows, key=lambda r: r["start_utc"])


def in_window(ts, windows):
    for w in windows:
        if w["start_utc"] <= ts <= w["end_utc"]:
            return w
    return None


def rand_ts(rng, start, end, business_hours=True):
    span = int((end - start).total_seconds())
    while True:
        ts = start + timedelta(seconds=rng.randrange(span))
        if not business_hours:
            return ts
        if ts.weekday() < 5 and 7 <= ts.hour < 18:
            return ts


def corp_ip(rng):
    return f"192.0.2.{rng.randrange(10, 60)}"


def identity_audit(rng, windows):
    rows = []

    # Benign admin work, inside change windows, with tickets.
    for w in windows:
        if w["end_utc"] < WINDOW_START or w["start_utc"] > LAB_NOW:
            continue
        for _ in range(rng.randrange(4, 9)):
            ts = w["start_utc"] + timedelta(minutes=rng.randrange(0, 235))
            app = rng.choice(KNOWN_APPS)
            op = rng.choice(["Update application", "Consent to application",
                             "Add service principal credentials", "Add member to role"])
            rows.append({
                "timestamp_utc": ts,
                "operation": op,
                "actor": f"{rng.choice(ADMINS)}@{DOMAIN}",
                "actor_type": "User",
                "target": app[0],
                "target_app_id": app[1],
                "publisher_verified": app[2],
                "permissions": app[3] if op == "Consent to application" else "",
                "consent_type": "Admin" if op == "Consent to application" else "",
                "ip_address": corp_ip(rng),
                "change_ticket": w["ticket"],
            })

    # Benign day-to-day directory changes during business hours.
    for _ in range(260):
        ts = rand_ts(rng, WINDOW_START, LAB_NOW)
        op = rng.choice(OPERATIONS_BENIGN)
        target = f"{rng.choice(USERS)}@{DOMAIN}"
        rows.append({
            "timestamp_utc": ts,
            "operation": op,
            "actor": f"{rng.choice(ADMINS)}@{DOMAIN}",
            "actor_type": "User",
            "target": target,
            "target_app_id": "",
            "publisher_verified": "",
            "permissions": "",
            "consent_type": "",
            "ip_address": corp_ip(rng),
            "change_ticket": "" if op in ("Reset user password", "Update user") else f"REQ-{rng.randrange(20000, 29999)}",
        })

    # Noise: low-risk user consents to verified apps, no ticket. Not findings.
    for _ in range(14):
        ts = rand_ts(rng, WINDOW_START, LAB_NOW)
        app = rng.choice([KNOWN_APPS[1], KNOWN_APPS[2], KNOWN_APPS[4]])
        rows.append({
            "timestamp_utc": ts,
            "operation": "Consent to application",
            "actor": f"{rng.choice(USERS)}@{DOMAIN}",
            "actor_type": "User",
            "target": app[0],
            "target_app_id": app[1],
            "publisher_verified": True,
            "permissions": app[3],
            "consent_type": "User",
            "ip_address": corp_ip(rng),
            "change_ticket": "",
        })

    # PLANTED 1 and 2: user consent to unverified apps with mail scope, off hours.
    rows.append({
        "timestamp_utc": datetime(2027, 2, 6, 3, 12, 41, tzinfo=UTC),
        "operation": "Consent to application",
        "actor": f"j.okafor@{DOMAIN}",
        "actor_type": "User",
        "target": "MailSync Pro",
        "target_app_id": "f9e2b7a0-7781",
        "publisher_verified": False,
        "permissions": "Mail.Read offline_access User.Read",
        "consent_type": "User",
        "ip_address": "203.0.113.45",
        "change_ticket": "",
    })
    rows.append({
        "timestamp_utc": datetime(2027, 2, 9, 22, 47, 5, tzinfo=UTC),
        "operation": "Consent to application",
        "actor": f"m.ruiz@{DOMAIN}",
        "actor_type": "User",
        "target": "DocView Connect",
        "target_app_id": "f9e2b7a0-9134",
        "publisher_verified": False,
        "permissions": "Mail.Read Files.Read.All offline_access",
        "consent_type": "User",
        "ip_address": "198.51.100.23",
        "change_ticket": "",
    })
    # PLANTED 3: credentials added to an existing service principal, Sunday 02:14, same IP as planted 1.
    rows.append({
        "timestamp_utc": datetime(2027, 2, 14, 2, 14, 9, tzinfo=UTC),
        "operation": "Add service principal credentials",
        "actor": f"j.okafor@{DOMAIN}",
        "actor_type": "User",
        "target": "PLM Bridge",
        "target_app_id": "a1f0c3d2-0001",
        "publisher_verified": True,
        "permissions": "",
        "consent_type": "",
        "ip_address": "203.0.113.45",
        "change_ticket": "",
    })
    # Decoy: legitimate credential rotation in the emergency window.
    rows.append({
        "timestamp_utc": datetime(2027, 2, 18, 13, 40, 0, tzinfo=UTC),
        "operation": "Add service principal credentials",
        "actor": f"cloud.ops@{DOMAIN}",
        "actor_type": "User",
        "target": "PLM Bridge",
        "target_app_id": "a1f0c3d2-0001",
        "publisher_verified": True,
        "permissions": "",
        "consent_type": "",
        "ip_address": "192.0.2.14",
        "change_ticket": "CHG-4199",
    })
    return sorted(rows, key=lambda r: r["timestamp_utc"])


VENDORS = [
    ("vnd.aerotest01", "AeroTest Services", "DE"),
    ("vnd.aerotest02", "AeroTest Services", "DE"),
    ("vnd.cncmaint01", "Precision CNC Maintenance", "US"),
    ("vnd.plcsupport", "Controls Integrator GmbH", "AT"),
]


def jumphost_sessions(rng):
    rows = []
    earliest = LAB_NOW - timedelta(days=JUMPHOST_RETENTION_DAYS)
    for _ in range(38):
        acct, vendor, country = rng.choice(VENDORS)
        start = rand_ts(rng, earliest, LAB_NOW)
        rows.append({
            "session_start_utc": start,
            "session_end_utc": start + timedelta(minutes=rng.randrange(15, 180)),
            "account": acct,
            "vendor": vendor,
            "source_ip": f"198.51.100.{rng.randrange(100, 140)}",
            "source_country": country,
            "target_host": rng.choice(["ENG-JMP-01", "ENG-JMP-01", "ENG-HMI-03"]),
            "protocol": "RDP",
        })
    return sorted(rows, key=lambda r: r["session_start_utc"])


def data_inventory():
    return [
        {"source": "Identity provider audit log", "file": "identity_audit.csv", "owner": "Identity team",
         "retention_days": 30, "earliest_available_utc": WINDOW_START, "forwarded_to_siem": "Yes",
         "notes": "Consent, credential, role, and user events"},
        {"source": "Change calendar", "file": "change_calendar.csv", "owner": "IT service management",
         "retention_days": 365, "earliest_available_utc": WINDOW_START - timedelta(days=7), "forwarded_to_siem": "No",
         "notes": "Approved change windows and tickets"},
        {"source": "OT jump host session log", "file": "jumphost_sessions.csv", "owner": "OT operations",
         "retention_days": JUMPHOST_RETENTION_DAYS, "earliest_available_utc": LAB_NOW - timedelta(days=JUMPHOST_RETENTION_DAYS),
         "forwarded_to_siem": "No", "notes": "Stored locally on the jump host; rolls over"},
        {"source": "Approved vendor list", "file": "approved_vendors.csv", "owner": "Procurement",
         "retention_days": "", "earliest_available_utc": "", "forwarded_to_siem": "No",
         "notes": "Vendor accounts allowed to use remote access"},
        {"source": "EDR, engineering workstations", "file": "(not provided in lab)", "owner": "SOC",
         "retention_days": 90, "earliest_available_utc": LAB_NOW - timedelta(days=90), "forwarded_to_siem": "Yes",
         "notes": "IT side only; OT hosts not covered"},
        {"source": "Passive OT network monitoring", "file": "(not deployed)", "owner": "OT operations",
         "retention_days": 0, "earliest_available_utc": "", "forwarded_to_siem": "No",
         "notes": "Not deployed"},
    ]


def fmt(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, bool):
        return "true" if v else "false"
    return v


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: fmt(v) for k, v in r.items()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).parent / "data"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    windows = change_windows()
    write_csv(out / "change_calendar.csv", windows)
    write_csv(out / "identity_audit.csv", identity_audit(rng, windows))
    write_csv(out / "jumphost_sessions.csv", jumphost_sessions(rng))
    write_csv(out / "approved_vendors.csv",
              [{"account": a, "vendor": v, "allowed_country": c} for a, v, c in VENDORS])
    write_csv(out / "data_inventory.csv", data_inventory())
    print(f"Wrote lab data to {out}")


if __name__ == "__main__":
    main()
