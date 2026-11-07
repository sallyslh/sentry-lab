#!/usr/bin/env python3
"""
Automatic responder (IDS + active response, like fail2ban).

Runs inside the TARGET's network (network_mode: service:target). It reads
Suricata's eve.json; when an alert from a selected rule arrives, it adds a
firewall rule on the target that drops all traffic to and from that machine,
for a set time (or until unblocked). Suricata itself still only detects.

Shared folder /response (with the attack panel):
  config.json   written by the panel: {"enabled", "sids", "duration"}
  status.json   written here: current blocks
  unblock       written by the panel: "all" or one IP address
"""
import json
import os
import socket
import subprocess
import time

EVE = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
DIR = os.environ.get("RESPONSE_DIR", "/response")
STATUS, CONFIG, UNBLOCK = (os.path.join(DIR, n) for n in ("status.json", "config.json", "unblock"))
DEFAULT_SIDS = [int(x) for x in os.environ.get(
    "BLOCK_SIDS", "1000001 1000002 1000003 1000004 1000005 1000006 1000007").replace(",", " ").split()]
DEFAULT_DURATION = int(os.environ.get("BLOCK_SECONDS", "20"))
CHAIN = "RESPONDER"
NAMES = {1000001: "Port scan", 1000002: "Password guessing", 1000003: "NULL scan",
         1000004: "Xmas scan", 1000005: "Website flood", 1000006: "Slow scan",
         1000007: "Data theft"}

blocks = {}


def ipt(*args):
    return subprocess.run(["iptables", *args], capture_output=True, text=True)


def setup_chain():
    ipt("-N", CHAIN)
    ipt("-F", CHAIN)
    for hook in ("INPUT", "OUTPUT"):
        if ipt("-C", hook, "-j", CHAIN).returncode != 0:
            ipt("-I", hook, "1", "-j", CHAIN)


def my_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def config():
    cfg = {"enabled": True, "sids": DEFAULT_SIDS, "duration": DEFAULT_DURATION}
    try:
        with open(CONFIG) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save():
    cfg = config()
    tmp = STATUS + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"running": True, "config": cfg, "blocks": blocks, "updated": time.time()}, f)
    os.replace(tmp, STATUS)


def block(ip, sid, ts, duration):
    if ip in blocks:
        return
    r1 = ipt("-A", CHAIN, "-s", ip, "-j", "DROP")
    r2 = ipt("-A", CHAIN, "-d", ip, "-j", "DROP")
    ok = r1.returncode == 0 and r2.returncode == 0
    now = time.time()
    blocks[ip] = {"since": now, "until": now + duration if duration > 0 else None,
                  "alert_ts": ts, "sid": sid, "rule": f"Rule {sid - 1000000}",
                  "name": NAMES.get(sid, "Alert"), "ok": ok,
                  "error": None if ok else (r1.stderr or r2.stderr).strip()}
    print(f"BLOCKED {ip} for {duration or 'manual'} s after {NAMES.get(sid)} (sid {sid}) ok={ok}", flush=True)
    save()


def unblock(ip):
    if ip not in blocks:
        return
    ipt("-D", CHAIN, "-s", ip, "-j", "DROP")
    ipt("-D", CHAIN, "-d", ip, "-j", "DROP")
    del blocks[ip]
    print(f"UNBLOCKED {ip}", flush=True)
    save()


def handle_unblock_request():
    if not os.path.exists(UNBLOCK):
        return
    try:
        with open(UNBLOCK) as f:
            what = f.read().strip()
        os.remove(UNBLOCK)
    except OSError:
        return
    if what in ("", "all"):
        ipt("-F", CHAIN)
        blocks.clear()
        print("UNBLOCKED all", flush=True)
        save()
    else:
        unblock(what)


def main():
    me = my_ip()
    setup_chain()
    save()
    print(f"Responder running in the target's network ({me}).", flush=True)
    pos, buf, last_save = None, "", 0
    while True:
        handle_unblock_request()
        now = time.time()
        for ip in [i for i, b in blocks.items() if b["until"] and b["until"] <= now]:
            unblock(ip)
        if now - last_save > 2:
            save()
            last_save = now
        try:
            size = os.path.getsize(EVE)
            if pos is None:
                pos = size
            if size < pos:
                pos = 0
            if size > pos:
                with open(EVE, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    buf += f.read()
                    pos = f.tell()
                *lines, buf = buf.split("\n")
                cfg = config()
                for line in lines:
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if ev.get("event_type") != "alert" or not cfg.get("enabled"):
                        continue
                    sid = ev.get("alert", {}).get("signature_id")
                    if sid not in cfg.get("sids", []):
                        continue
                    src, dst = ev.get("src_ip"), ev.get("dest_ip")
                    other = dst if src == me else src
                    if other and other != me:
                        block(other, sid, ev.get("timestamp"), int(cfg.get("duration", 0)))
        except FileNotFoundError:
            pass
        except Exception as e:
            print("responder error:", e, flush=True)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
