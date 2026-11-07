#!/bin/sh
# Phase 4: Evasion test. Same objective as Scenario 1 (port scan) but slow
# and fragmented, to test whether it stays under Rule 1's rate threshold
# (20 SYNs / 10s) and/or evades flag-based matching via fragmentation.
# This is expected to produce FEWER or NO alerts - that is the point.
# Port range is limited to 15 to keep run time practical: at -T1 (~15s
# delay between probes), 15 ports already takes ~3-4 minutes, and the
# evasion point (staying under 20 SYNs/10s) holds regardless of port count.
# Usage: evasion_slow_scan.sh <run_number>
RUN="${1:-1}"
echo "=== Evasion test (slow+fragmented scan) run $RUN: $(date -u +%FT%TZ) ==="
nmap -sS -T1 -f -p 1-15 target
echo "=== end run $RUN ==="
