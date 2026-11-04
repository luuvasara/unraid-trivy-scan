#!/bin/bash
# action-test.sh - include/action.php behind a request prologue that behaves like Unraid's local_prepend.php
# (php auto_prepend_file, the real file): it validates csrf_token from $_POST, else from the X-CSRF-Token header, and then
# unset()s $_POST['csrf_token']. The 2026.10.27-2026.11.01 releases failed every button with "invalid csrf_token"
# because action.php re-checked only $_POST. Served by php -S on 127.0.0.1; the cve-lens script is a stub.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-cve-lens
W=$HERE/tests/.work/action; rm -rf "$W"; mkdir -p "$W/root/plugins"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
TOKEN=0123456789ABCDEF
printf 'csrf_token="%s"\n' "$TOKEN" >"$W/var.ini"
printf '#!/bin/sh\necho "stub $1"\n' >"$W/script"; chmod 755 "$W/script"
ln -s "$P" "$W/root/plugins/unraid-cve-lens"
# The prologue is a byte-for-byte copy of Unraid 7.3.4's local_prepend.php (tests/fixtures/unraid-7.3.4, md5 checked by
# tests/real-unraid-test.sh). It reads state/var.ini relative to its chdir('/usr/local/emhttp'); the docroot plays that directory.
mkdir -p "$W/root/state"; cp "$W/var.ini" "$W/root/state/var.ini"
printf '<?php chdir(%s); require %s;\n' "'$W/root'" "'$HERE/tests/fixtures/unraid-7.3.4/local_prepend.php'" >"$W/prepend.php"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
UTS_VARINI=$W/var.ini UTS_SCRIPT=$W/script php -d auto_prepend_file="$W/prepend.php" -d display_errors=0 -d short_open_tag=1 -S 127.0.0.1:"$PORT" -t "$W/root" >"$W/server.log" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
U=http://127.0.0.1:$PORT/plugins/unraid-cve-lens/include/action.php
req() { curl -s -w ' %{http_code}' "$@" "$U"; }
for a in start stop update-db; do
  R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=$a&csrf_token=$TOKEN")
  [ "$R" = "{\"ok\":true,\"message\":\"stub $a\"} 200" ] && ok "button '$a' (body + header token, as report.js sends): $R" || bad "button '$a': $R"
done
R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=start")
[ "${R##* }" = 200 ] && ok "header-only token accepted" || bad "header-only token: $R"
R=$(req --data "action=start&csrf_token=$TOKEN")
[ "${R##* }" = 200 ] && ok "body-only token accepted (prologue checked it)" || bad "body-only token: $R"
R=$(req --data "action=start&csrf_token=WRONGWRONGWRONG0")
[ "$R" = " 200" ] && ok "wrong token stopped by the prologue (HTTP 200, empty body: csrf_terminate has no status code)" || bad "wrong token: $R"
R=$(req --data "action=start")
[ "$R" = " 200" ] && ok "missing token stopped by the prologue" || bad "missing token: $R"
R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=rm-rf")
[ "${R##* }" = 400 ] && ok "unknown action: 400" || bad "unknown action: $R"
grep -q "X-CSRF-Token" "$P/assets/report.js" && ok "report.js sends the X-CSRF-Token header" || bad "report.js does not send X-CSRF-Token"
# Browsers must fetch the new report.js after an update. build.sh pins every file mtime to the release day, so a
# filemtime() cache key stayed the same between two releases of one day and kept the old (broken) script cached.
if grep -n 'filemtime' "$P"/*.page; then bad "a page still derives its asset cache key from filemtime"; else ok "asset cache keys are content hashes, not mtimes"; fi
exit $fail
