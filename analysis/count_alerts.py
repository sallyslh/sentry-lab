#!/usr/bin/env python3
"""
Reads Suricata's eve.json and produces per-scenario alert counts.

Usage:
    python analysis/count_alerts.py <path-to-eve.json> --benign-ip <IP> [--out results/summary.csv]

eve.json lives in the 'suricata-logs' Docker volume. Copy it out first, e.g.:
    docker compose cp suricata:/var/log/suricata/eve.json results/eve.json

The benign container's IP changes between rebuilds (Docker assigns it when
the network is created), so look it up each time before running this:
    docker compose exec benign hostname -i

Example:
    python analysis/count_alerts.py results/eve.json --benign-ip 172.21.0.4
"""
import argparse
import json
import sys
from collections import defaultdict

# Maps our local.rules signature IDs to a human-readable scenario label.
SID_TO_SCENARIO = {
    1000001: "Scenario 1: Port scan (SYN)",
    1000002: "Scenario 2: SSH brute force",
    1000003: "Scenario 3: Malformed (NULL scan)",
    1000004: "Scenario 3: Malformed (Xmas scan)",
    1000005: "Rule 5: HTTP rate (sensitivity test)",
    1000006: "Rule 6: Low-and-slow scan (evasion companion rule)",
    1000007: "Rule 7: Bulk transfer detection (exfiltration fix)",
}


def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("eve_json")
    ap.add_argument("--benign-ip", required=True, help="Benign container's IP (docker compose exec benign hostname -i)")
    ap.add_argument("--out", default="results/summary.csv")
    args = ap.parse_args()

    events = load_events(args.eve_json)
    alerts = [e for e in events if e.get("event_type") == "alert"]

    by_scenario = defaultdict(int)
    by_scenario_src = defaultdict(set)
    false_alarms = defaultdict(int)
    unknown_sids = defaultdict(int)

    for a in alerts:
        sid = a.get("alert", {}).get("signature_id")
        src = a.get("src_ip", "?")
        dest = a.get("dest_ip", "?")
        label = SID_TO_SCENARIO.get(sid)
        if label is None:
            unknown_sids[sid] += 1
            continue
        by_scenario[label] += 1
        by_scenario_src[label].add(src)
        # Check both sides: most rules are one-directional (src is always
        # the connecting client), but bidirectional rules (<>, e.g. Rule 7)
        # can fire with the target as src responding to benign as dest -
        # that's still a false alarm caused by benign traffic, just not
        # visible from src_ip alone.
        if src == args.benign_ip or dest == args.benign_ip:
            false_alarms[label] += 1

    print(f"Total alert events: {len(alerts)}")
    print()
    print(f"{'Scenario':40s} {'Alerts':>8s} {'Distinct src IPs':>18s} {'False alarms':>14s}")
    for label in sorted(by_scenario):
        print(f"{label:40s} {by_scenario[label]:>8d} {len(by_scenario_src[label]):>18d} {false_alarms[label]:>14d}")

    if unknown_sids:
        print("\nAlerts from rules not in SID_TO_SCENARIO (e.g. ET Open, if enabled):")
        for sid, count in unknown_sids.items():
            print(f"  sid={sid}: {count} alerts")

    import csv
    import os
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "alert_count", "distinct_src_ips", "false_alarms"])
        for label in sorted(by_scenario):
            w.writerow([label, by_scenario[label], len(by_scenario_src[label]), false_alarms[label]])
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    sys.exit(main())
