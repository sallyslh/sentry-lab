#!/bin/sh
# Scenario 3: Malformed packets - NULL scan and Xmas scan against the target.
# Usage: scenario3_malformed.sh <run_number>
RUN="${1:-1}"
echo "=== Scenario 3 (malformed packets) run $RUN: $(date -u +%FT%TZ) ==="
echo "-- NULL scan --"
nmap -sN -p 1-100 target
echo "-- Xmas scan --"
nmap -sX -p 1-100 target
echo "=== end run $RUN ==="
