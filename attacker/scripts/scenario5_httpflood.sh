#!/bin/sh
# Scenario 5: HTTP flood - a genuine true-positive test for Rule 5
# (suricata/rules/local.rules), which needs 4+ connections to port 80
# within 10s to fire. None of scenarios 1-3 actually exercise this: the
# port scan touches port 80 only once, brute force targets port 22, and
# the malformed-packet scans don't use flags:S. Without this scenario,
# Rule 5 would only ever have been tested against benign traffic, which
# proves it stays quiet but not that it still works.
# Usage: scenario5_httpflood.sh <run_number>
RUN="${1:-1}"
echo "=== Scenario 5 (HTTP flood, true-positive test) run $RUN: $(date -u +%FT%TZ) ==="
for i in 1 2 3 4 5 6; do
    (echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w 2 target 80 >/dev/null 2>&1 && echo "req $i ok") &
done
wait
echo "=== end run $RUN ==="
