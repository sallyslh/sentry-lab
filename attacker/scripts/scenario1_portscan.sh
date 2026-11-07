#!/bin/sh
# Scenario 1: Port scan (SYN scan) against the target.
# Usage: scenario1_portscan.sh <run_number>
RUN="${1:-1}"
echo "=== Scenario 1 (port scan) run $RUN: $(date -u +%FT%TZ) ==="
nmap -sS -p 1-1000 target
echo "=== end run $RUN ==="
