# IDS Lab — Suricata Detection Testing

A containerized lab for testing Suricata IDS detection against several attack scenarios, with concurrent benign traffic to measure false alarms.

## Requirements

- Docker Desktop with Docker Compose v2
- On Windows with WSL2: at least ~4GB free RAM for the WSL2 VM (see Memory note below)

## Pinned versions

- Suricata 7.0.17 (`jasonish/suricata:7.0.17`)
- EveBox 0.31.0 (`jasonish/evebox:0.31.0`)

## Start the lab

```bash
docker compose up -d
docker compose ps
```

All 5 containers (`target`, `suricata`, `attacker`, `benign`, `evebox`) should show as "Up".

## View alerts

Open `http://localhost:5636` in a browser. EveBox reads Suricata's `eve.json` directly (SQLite backend, no auth/TLS — local lab only, not for exposed use).

## Run each attack scenario

Run from the project root. On Windows Git Bash, prefix commands with `MSYS_NO_PATHCONV=1` so paths aren't rewritten.

```bash
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/scenario1_portscan.sh <run_number>
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/scenario2_sshbruteforce.sh <run_number>
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/scenario3_malformed.sh <run_number>
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/scenario4_exfiltration.sh <run_number>
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/scenario5_httpflood.sh <run_number>
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/evasion_slow_scan.sh <run_number>
```

Or run the full experiment set (5 trials of scenarios 1–3, 5 evasion trials, 1 exfiltration trial, spaced apart):

```bash
MSYS_NO_PATHCONV=1 docker compose exec attacker /scripts/run_all.sh
```

## Attack panel (interactive demo)

A web page for running the attacks with clicks instead of commands. Open `http://localhost:8080` after `docker compose up -d`.

Across the top, a story bar (Recon → Break in → Steal → Disrupt) turns red when Suricata catches each step.

| Tab | What you do | Real traffic | Rule |
| --- | --- | --- | --- |
| Website | Browse the target's demo store (CedarShop) | One HTTP visit per page | 5 (4 visits in 10 s) |
| Scan ports | Fast scan of ports 1–1000, or slow scan of 1–15 | One TCP connection per port | 1 fast, 6 slow |
| Build a packet | Tick TCP flags, send one packet | hping3, one packet | 3 (no flags), 4 (FIN+PSH+URG) |
| Break in & steal | Guess the SSH password in a terminal, then steal a 20 MB file | One SSH login per guess; real SSH session; real download | 2 (5 logins in 10 s), 7 (> 1 MB) |
| Flood | Send 1–20 website connections at once | N HTTP connections | 5 |
| Original scripts | One button per script in `attacker/scripts/` | The same scripts, unchanged | 1–7 |

The right side shows live alerts read from Suricata's `eve.json` (YOU = attacker, NORMAL USER = false alarm), Suricata's packets seen and dropped, and bars showing how close this page's own clicks are to each rule's limit. The bars never decide anything: only Suricata does.

The command-line scripts still work exactly as before, and the measured results in `results/` come from them. Code: `attacker/panel/` (Python standard library, no install). Website: `target/site/`.

Notes: the attacker container also joins the `dash` network so the browser can reach the page, published on 127.0.0.1 only; attack traffic still goes to `target` on the internal `lab` network. The Steal tab creates `customers_database.sql` (random bytes, no real data) in labuser's home on the target.

## Defender: automatic response (IDS + action)

Suricata only detects. The `responder` container adds the action: it reads Suricata's `eve.json`, and when an alert from a selected rule arrives, it adds a firewall rule on the target that drops all traffic to and from that machine for a short time (default 20 s), then removes it. This is IDS + automatic response (like fail2ban), not an inline IPS: the block comes about a second after the alert, so a little traffic gets through first.

Control it live in the attack panel ("Defender" card):
- **Detect only (IDS)** or **Detect + block**
- which rules cause a block (default: all seven)
- how long a block lasts (15 s to 60 s, or until you press Unblock)

When you are blocked, a red bar shows a countdown and an **Unblock now** button, so a demo can go through every step. If the normal user is blocked by a false alarm, the Defender card shows it, which is the main risk of automatic blocking.

`docker compose logs responder` shows each block and unblock. The responder shares the target's network, like Suricata: if the target container is rebuilt, run `docker compose down` then `docker compose up -d`.

## Collect and verify results

```bash
docker compose exec benign hostname -i                      # find the benign container's IP
docker compose cp suricata:/var/log/suricata/eve.json results/eve.json
python analysis/count_alerts.py results/eve.json --benign-ip <benign-ip> --out results/summary.csv
python results/verify_trials.py                              # per-trial detection check, not just raw counts
```

## Detection rules

All 7 custom rules are in `suricata/rules/local.rules`, with inline comments documenting the full tuning history for each one.

## Stop the lab

```bash
docker compose down
```

## Memory note (Windows / Docker Desktop)

On an 8GB RAM machine, Docker Desktop's WSL2 VM can exhaust available memory and crash ("Docker Engine stopped"). Cap it by creating `.wslconfig` in your Windows user folder (`C:\Users\<you>\.wslconfig`):

```
[wsl2]
memory=4GB
```

Restart Docker Desktop after creating/editing this file. If the engine still won't start, close other applications first and try again.
