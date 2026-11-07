#!/bin/sh
# Scenario 4 (optional): Large outbound transfer, target -> attacker,
# to test whether a policy-style violation (bulk data leaving the service)
# is caught by our current rules. Expected: likely MISSED, since none of
# our 4 rules inspect transfer volume - this is a deliberate, reportable gap.
# Usage: scenario4_exfiltration.sh <run_number>
RUN="${1:-1}"
echo "=== Scenario 4 (large outbound transfer) run $RUN: $(date -u +%FT%TZ) ==="
sshpass -p labpass123 scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    labuser@target:/var/www/html/index.html /tmp/exfil_run${RUN}.html
dd if=/dev/urandom of=/tmp/bigfile bs=1M count=20 2>/dev/null
sshpass -p labpass123 scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    /tmp/bigfile labuser@target:/tmp/bigfile_uploaded 2>/dev/null || true
echo "=== end run $RUN ==="
