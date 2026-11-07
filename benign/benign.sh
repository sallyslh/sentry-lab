#!/bin/sh
# Benign client: HTTP request on a jittered 3-10s interval, normal SSH login
# roughly every 3rd request. Real user traffic is never perfectly periodic,
# so the jitter is realistic - not added just to force false positives - but
# it does mean occasional bursts can land close together, which is what lets
# Rule 5 (suricata/rules/local.rules) legitimately misfire sometimes.
# (Range was 3-7s, then 3-8s, in earlier tuning passes - see local.rules'
# Rule 5 comment for the full before/after history.)
# Each action is logged with a timestamp (used later for the false-alarm count).
i=0
while true; do
    if curl -s -o /dev/null -w '%{http_code}' http://target/ >/tmp/code; then
        echo "$(date -u +%FT%TZ) BENIGN http_get status=$(cat /tmp/code)"
    else
        echo "$(date -u +%FT%TZ) BENIGN http_get FAILED"
    fi
    if [ $((i % 3)) -eq 0 ]; then
        if sshpass -p labpass123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR labuser@target 'echo ok' >/dev/null; then
            echo "$(date -u +%FT%TZ) BENIGN ssh_login ok"
        else
            echo "$(date -u +%FT%TZ) BENIGN ssh_login FAILED"
        fi
    fi
    i=$((i + 1))
    # Jittered sleep: 3-10 seconds, drawn from a random byte (POSIX sh has no $RANDOM).
    jitter=$(( $(od -An -N1 -tu1 /dev/urandom) % 8 + 3 ))
    sleep "$jitter"
done
