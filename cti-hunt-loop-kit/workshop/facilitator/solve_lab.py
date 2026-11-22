#!/usr/bin/env python3
"""Reference solution for the PIR-to-Proof lab (facilitator use).

Runs the preflight check and both hunts against the synthetic data and prints
the expected outcome for each hypothesis. Participants can reach the same
answers with a spreadsheet; this script is the answer key.

Usage:
    python solve_lab.py [--data ../lab/data]

License: MIT.
"""

import argparse
from pathlib import Path

import pandas as pd

HUNT_WINDOW_DAYS = 30
SENSITIVE_SCOPES = ("Mail.Read", "Mail.ReadWrite", "Files.Read.All", "Files.ReadWrite.All")


def load(data):
    ts = lambda df, cols: df.assign(**{c: pd.to_datetime(df[c], utc=True) for c in cols})
    audit = ts(pd.read_csv(data / "identity_audit.csv", dtype=str, keep_default_na=False), ["timestamp_utc"])
    windows = ts(pd.read_csv(data / "change_calendar.csv"), ["start_utc", "end_utc"])
    sessions = ts(pd.read_csv(data / "jumphost_sessions.csv"), ["session_start_utc", "session_end_utc"])
    vendors = pd.read_csv(data / "approved_vendors.csv")
    inventory = pd.read_csv(data / "data_inventory.csv", keep_default_na=False)
    return audit, windows, sessions, vendors, inventory


def outside_windows(ts, windows):
    return ~ts.apply(lambda t: ((windows.start_utc <= t) & (t <= windows.end_utc)).any())


def preflight(inventory, lab_now):
    print("PREFLIGHT")
    window_start = lab_now - pd.Timedelta(days=HUNT_WINDOW_DAYS)
    for _, r in inventory.iterrows():
        if r["file"].startswith("("):
            continue
        earliest = r["earliest_available_utc"]
        if not earliest:
            print(f"  {r['source']}: reference list, no time coverage needed")
            continue
        earliest = pd.to_datetime(earliest, utc=True)
        covered = earliest <= window_start
        days = (lab_now - max(earliest, window_start)).days
        status = "PASS" if covered else "FAIL"
        print(f"  {r['source']}: {status} ({days} of {HUNT_WINDOW_DAYS} days covered)")
    print()


def hunt_a(audit, windows):
    print("HYPOTHESIS A: cloud identity (T1528, T1098.001)")
    off = outside_windows(audit.timestamp_utc, windows)
    no_ticket = audit.change_ticket == ""

    consents = audit[
        (audit.operation == "Consent to application")
        & (audit.consent_type == "User")
        & (audit.publisher_verified == "false")
        & audit.permissions.str.contains("|".join(SENSITIVE_SCOPES))
        & no_ticket & off
    ]
    creds = audit[
        (audit.operation == "Add service principal credentials") & no_ticket & off
    ]
    hits = pd.concat([consents, creds]).sort_values("timestamp_utc")
    cols = ["timestamp_utc", "operation", "actor", "target", "permissions", "ip_address"]
    print(hits[cols].to_string(index=False))
    shared_ips = hits.ip_address.value_counts()
    print("\n  Pivot: IPs seen in more than one hit:", ", ".join(shared_ips[shared_ips > 1].index) or "none")
    print("  Expected outcome: SUPPORTED FINDING (3 events, 2 users, shared IP 203.0.113.45)\n")


def hunt_b(sessions, vendors, inventory, lab_now):
    print("HYPOTHESIS B: OT vendor remote access (ICS T0822)")
    merged = sessions.merge(vendors, on="account", how="left")
    unapproved = merged[merged.vendor_y.isna() | (merged.source_country != merged.allowed_country)]
    first = sessions.session_start_utc.min()
    print(f"  Sessions available: {len(sessions)}, earliest {first:%Y-%m-%d}")
    print(f"  Sessions from unapproved accounts or countries: {len(unapproved)}")
    print(f"  Hunt window starts {(lab_now - pd.Timedelta(days=HUNT_WINDOW_DAYS)):%Y-%m-%d}; "
          f"data covers only the last {(lab_now - first).days + 1} days")
    print("  Expected outcome: INCONCLUSIVE (nothing found, but retention fails preflight)")
    print("  Action: collection requirement to forward jump host logs to the SIEM with >= 90-day retention\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "lab" / "data"))
    args = ap.parse_args()
    audit, windows, sessions, vendors, inventory = load(Path(args.data))
    lab_now = pd.Timestamp("2027-03-03T00:00:00Z")
    preflight(inventory, lab_now)
    hunt_a(audit, windows)
    hunt_b(sessions, vendors, inventory, lab_now)


if __name__ == "__main__":
    main()
