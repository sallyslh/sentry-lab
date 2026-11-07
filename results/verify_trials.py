#!/usr/bin/env python3
"""One-off verification: map alerts to specific trial windows to confirm
per-trial detected/missed status, not just raw alert counts."""
import json
from datetime import datetime, timedelta

def parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

# (label, start_time, duration_seconds, expected_sids)
trials = []
s1_starts = ["16:09:23","16:09:48","16:10:09","16:10:31","16:10:51"]
for i, t in enumerate(s1_starts, 1):
    trials.append((f"Scenario1 run{i}", parse(f"2026-10-28T{t}Z"), 10, [1000001]))
s2_starts = ["16:11:12","16:11:44","16:12:17","16:12:50","16:13:22"]
for i, t in enumerate(s2_starts, 1):
    trials.append((f"Scenario2 run{i}", parse(f"2026-10-28T{t}Z"), 20, [1000002]))
s3_starts = ["16:13:55","16:14:19","16:14:42","16:15:07","16:15:30"]
for i, t in enumerate(s3_starts, 1):
    trials.append((f"Scenario3 run{i}", parse(f"2026-10-28T{t}Z"), 20, [1000003, 1000004]))
evasion_starts = ["16:15:53","16:20:29","16:25:05","16:29:41","16:34:17"]
for i, t in enumerate(evasion_starts, 1):
    trials.append((f"Evasion run{i} (Rule1)", parse(f"2026-10-28T{t}Z"), 260, [1000001]))
    trials.append((f"Evasion run{i} (Rule6)", parse(f"2026-10-28T{t}Z"), 260, [1000006]))

alerts = []
with open("eve.json", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") == "alert":
            ts = e["timestamp"].split(".")[0].replace("+00:00", "")
            alerts.append((datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S"), e["alert"]["signature_id"], e["src_ip"]))

print(f"{'Trial':30s} {'Detected':>10s} {'MatchCount':>11s}")
for label, start, dur, sids in trials:
    end = start + timedelta(seconds=dur)
    matches = [a for a in alerts if start <= a[0] <= end and a[1] in sids]
    print(f"{label:30s} {'YES' if matches else 'NO':>10s} {len(matches):>11d}")
