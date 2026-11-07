#!/bin/sh
# Runs every scenario 5 times each, with a pause between runs so bursts
# don't overlap and confuse the alert counts. Run this from inside the
# attacker container: docker compose exec attacker /scripts/run_all.sh
set -e
RUNS=5
SCRIPTS="scenario1_portscan.sh scenario2_sshbruteforce.sh scenario3_malformed.sh"

for s in $SCRIPTS; do
    for i in $(seq 1 $RUNS); do
        sh /scripts/$s "$i"
        sleep 20
    done
done

# Evasion test, run 5x like the core scenarios (each run is slow, ~4-5 min,
# due to -T1 timing - this whole block takes roughly 20-25 minutes).
for i in $(seq 1 $RUNS); do
    sh /scripts/evasion_slow_scan.sh "$i"
    sleep 20
done

# Optional exfiltration scenario: run once. Its outcome is structural (no
# rule inspects transfer volume), not timing-dependent, so repeating it
# doesn't add new information the way the evasion test's repeats do.
sh /scripts/scenario4_exfiltration.sh 1

echo "All scenarios complete. Now run the alert-counting script on the host:"
echo "  python analysis/count_alerts.py"
