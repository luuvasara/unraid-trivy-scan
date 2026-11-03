#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# real-unraid-test.sh - the plugin behind COPIES OF THE REAL Unraid 7.3.4 FILES in tests/fixtures/unraid-7.3.4/ (taken
# byte for byte from a 7.3.4 server, md5 in the file list below; nothing is written from a summary):
#   update.php, update.htm, Wrappers.php   Settings Apply:  form -> /update.php -> validate.php -> cfg -> trivy-scan apply
#   local_prepend.php                      the request prologue (auto_prepend_file): CSRF check, runs for every request
#   emhttp_event.dispatch                  lines 82-106 of /usr/local/sbin/emhttp_event (how event/ scripts are run)
#   evalContent.php                        how a page's Cond is evaluated
# The only differences from a server: paths (docroot, flash, /var/run) are redirected with the UTS_* variables, and
# the dispatcher's plugin directory is substituted. What is NOT covered (needs the real GUI): the browser side of
# update.htm (the progress frame, the reload), emhttpd actually firing events, nginx/auth. See the 07b notes.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan
FX=$HERE/tests/fixtures/unraid-7.3.4
W=$HERE/tests/.work/real; rm -rf "$W"; mkdir -p "$W"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
# PLUGIN_SRC lets a run use an older tree (fail-on-old proof): PLUGIN_SRC=<dir with plugins/unraid-trivy-scan layout>
SRC=${PLUGIN_SRC:-$P}

# ---- the fixtures are the real files
declare -A MD5=([update.php]=595fd158ada84b600a64cd0aaa6b5b8c [update.htm]=19a10d9ef09f70f6e30e4258504cfe86 [local_prepend.php]=4e567395f3fe2c9d6a2672e7403478a1
                [Wrappers.php]=6bcb86c27b505eedb5fd4d22d6828f50 [evalContent.php]=054ca2278e455660a168069b591cfe57 [emhttp_event.dispatch]=9f471afb2b18875493b7060cb2b31334)
for f in "${!MD5[@]}"; do [ "$(md5sum <"$FX/$f" | cut -d' ' -f1)" = "${MD5[$f]}" ] || bad "fixture $f was modified"; done
ok "fixtures unmodified (md5 of the 7.3.4 originals)"

# ---------------------------------------------------------------- F1: event hook through the real dispatcher
EV=$W/ev; mkdir -p "$EV/plugins/unraid-trivy-scan"
cp -r "$SRC/." "$EV/plugins/unraid-trivy-scan/"
printf '#!/bin/sh\nsleep 2\necho "$1" >>%s/stub.log\n' "$W" >"$W/stub"; chmod 755 "$W/stub"
{ echo '#!/bin/bash'; sed "s#/usr/local/emhttp/plugins#$EV/plugins#g" "$FX/emhttp_event.dispatch"; } >"$W/dispatch.sh"
t0=$(date +%s.%N)
UTS_SCRIPT=$W/stub bash "$W/dispatch.sh" stopping_docker >"$W/dispatch.out" 2>&1
el=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
[ ! -s "$W/stub.log" ] && awk -v e="$el" 'BEGIN{exit !(e<1.0)}' && ok "event stopping_docker: dispatcher returns at once (${el}s) while the stop runs detached" || bad "event hook blocked or did nothing (${el}s, log: $(cat "$W/stub.log" 2>&1))"
sleep 3.5
[ "$(cat "$W/stub.log" 2>/dev/null)" = stop ] && ok "event stopping_docker: 'trivy-scan stop' ran (detached)" || bad "stop did not run: $(cat "$W/stub.log" 2>&1); $(cat "$W/dispatch.out")"
rm -f "$W/stub.log"; UTS_SCRIPT=$W/stub bash "$W/dispatch.sh" started >/dev/null 2>&1; sleep 2.5
[ ! -e "$W/stub.log" ] && ok "other events (started) do not stop a scan" || bad "event 'started' ran the stop"

# ---------------------------------------------------------------- the web root: real update.php + prologue
R=$W/root; mkdir -p "$R/plugins/dynamix/include" "$R/webGui/include/DefaultPageLayout" "$R/state" "$W/flash" "$W/run"
cp "$FX/update.php" "$FX/update.htm" "$R/"; cp "$FX/Wrappers.php" "$R/plugins/dynamix/include/"; cp "$FX/evalContent.php" "$R/webGui/include/DefaultPageLayout/"
cp -r "$SRC" "$R/plugins/unraid-trivy-scan"      # a copy: update.php refuses includes whose realpath is outside the docroot
chmod 755 "$R/plugins/unraid-trivy-scan/scripts/trivy-scan"
TOKEN=0123456789ABCDEF
printf 'csrf_token="%s"\nfsState="Started"\n' "$TOKEN" >"$R/state/var.ini"     # the prologue reads state/var.ini (local_prepend.php:39)
printf '#!/bin/sh\necho x >>%s/update_cron.log\n' "$W" >"$W/update_cron"; chmod 755 "$W/update_cron"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
export UTS_CFG=$W/flash/unraid-trivy-scan.cfg UTS_CRON_FILE=$W/flash/uts.cron UTS_UPDATE_CRON=$W/update_cron UTS_RUN=$W/run UTS_DATA=$W/data/unraid-trivy-scan \
       UTS_VARINI=$R/state/var.ini UTS_SCRIPT=$R/plugins/unraid-trivy-scan/scripts/trivy-scan UTS_PLUGIN_DIR=$R/plugins/unraid-trivy-scan
# local_prepend.php:23 does chdir('/usr/local/emhttp') and line 39 reads state/var.ini relative to it; here the docroot plays that directory
printf '<?php chdir(%s); require %s;\n' "'$R'" "'$FX/local_prepend.php'" >"$W/prepend.php"
( cd "$R" && php -d auto_prepend_file="$W/prepend.php" -d display_errors=0 -d short_open_tag=1 -S 127.0.0.1:"$PORT" -t "$R" >"$W/server.log" 2>&1 ) &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/update.htm" && break; sleep 0.1; done
B=http://127.0.0.1:$PORT

# ---------------------------------------------------------------- F3/F4: what the form carries
FORM=$(cd "$R" && php -d short_open_tag=1 "$HERE/tests/real-form.php" "$SRC/TrivyScanSettings.page")
ACTION=$(sed -n 1p <<<"$FORM")
[ "$ACTION" = /update.php ] && ok "settings form posts to /update.php" || bad "form action: $ACTION"
(cd "$R" && env -u UTS_CFG php -d short_open_tag=1 "$HERE/tests/real-form.php" "$SRC/TrivyScanSettings.page") | sed -n 2p | grep -q '%23file=unraid-trivy-scan%2Funraid-trivy-scan.cfg&' \
  && ok "#file is relative to /boot/config/plugins, as update.php:64 and the stock forms expect" || bad "#file is not the relative form"
grep -q 'csrf_token' <<<"$(sed -n 2p <<<"$FORM")" && bad "form still carries its own csrf_token field" || ok "form has no csrf_token field of its own (Unraid's BodyInlineJS.php:292 appends one to every form)"
post() { curl -s -w '\nHTTP %{http_code}' --data "$(sed -n 2p <<<"$1")&csrf_token=$TOKEN" "$B/update.php"; }   # csrf_token appended like BodyInlineJS does

# ---------------------------------------------------------------- Settings Apply, valid values
FORMV=$(cd "$R" && php -d short_open_tag=1 "$HERE/tests/real-form.php" "$SRC/TrivyScanSettings.page" 'SCHEDULE=30 3 * * 0' SCOPE=all TIMEOUT=45)
OUT=$(post "$FORMV")
grep -q 'HTTP 200' <<<"$OUT" && grep -q 'Scheduled scan: 30 3 \* \* 0' <<<"$OUT" && ok "Apply (valid): update.php ran apply, progress log says 'Scheduled scan: 30 3 * * 0'" || bad "valid apply output: $OUT"
grep -qx 'SCHEDULE="30 3 \* \* 0"' "$UTS_CFG" && grep -qx 'SCOPE="all"' "$UTS_CFG" && grep -qx 'TIMEOUT="45"' "$UTS_CFG" && ! grep -q 'csrf_token\|#' "$UTS_CFG" \
  && ok "Apply (valid): cfg written by the real update.php as KEY=\"value\" lines, no csrf_token, no #fields" || bad "cfg: $(cat "$UTS_CFG" 2>&1)"
[ "$(grep -v '^#' "$UTS_CRON_FILE" 2>/dev/null | cut -d' ' -f1-5)" = "30 3 * * 0" ] && [ -s "$W/update_cron.log" ] && ok "Apply (valid): cron entry written, update_cron called" || bad "cron: $(cat "$UTS_CRON_FILE" 2>&1)"
compgen -G "$W/flash/*cfg[0-9]*" >/dev/null && bad "stray atomic-write file left in flash" || ok "no stray temp file next to the cfg"

# ---------------------------------------------------------------- Settings Apply, refused values (F6)
CFG_BEFORE=$(md5sum <"$UTS_CFG"); CRON_BEFORE=$(md5sum <"$UTS_CRON_FILE")
FORMI=$(cd "$R" && php -d short_open_tag=1 "$HERE/tests/real-form.php" "$SRC/TrivyScanSettings.page" 'SCHEDULE=$(reboot) * * * *' TIMEOUT=2)
OUT=$(post "$FORMI")
[ "$(md5sum <"$UTS_CFG")" = "$CFG_BEFORE" ] && [ "$(md5sum <"$UTS_CRON_FILE")" = "$CRON_BEFORE" ] && ok "Apply (invalid): cfg and cron untouched" || bad "invalid apply changed files"
grep -q 'addLog(".*Settings NOT saved, invalid value for: SCHEDULE, TIMEOUT' <<<"$OUT" && ok "Apply (invalid): refusal goes through update.php's write_log (addLog) like the stock includes" || bad "refusal not in write_log style: $OUT"
grep -q 'Scheduled scan\|No scheduled scan' <<<"$OUT" && bad "Apply (invalid): misleading schedule line still printed: $(grep -o 'addLog.*' <<<"$OUT")" || ok "Apply (invalid): no 'Scheduled scan' line after a refused save"
grep -q 'Nothing was changed' <<<"$OUT" && ok "Apply (invalid): says nothing was changed" || bad "no 'Nothing was changed'"

# ---------------------------------------------------------------- F5: the real prologue's answer to a bad token
UTS_REPORT_JS=$SRC/assets/report.js node "$HERE/tests/action-ui.js" "$B" >"$W/ui.out" 2>&1
while IFS= read -r l; do case $l in ok*) ok "${l#ok   }" ;; *) bad "${l#FAIL }" ;; esac; done <"$W/ui.out"

# ---------------------------------------------------------------- F8: the tab's Cond through the real evalContent.php
cond() {   # cond <fsState> <cfg text>: evaluate the header tab's Cond like PageBuilder::page_enabled(), with the cfg path redirected
  local c; c=$(sed -n 's/^Cond="\(.*\)"$/\1/p' "$SRC/Vulnerabilities.page" | sed "s#/boot/config/plugins/unraid-trivy-scan/unraid-trivy-scan.cfg#$W/tab.cfg#")
  printf '%s' "$2" >"$W/tab.cfg"
  php -r 'function page_enabled($c, $var, $docroot) { $enabled = $evalSuccess = true; $evalContent = "\$enabled={$c};"; $evalFile = "tab"; include "$docroot/webGui/include/DefaultPageLayout/evalContent.php"; return ($enabled && $evalSuccess); }
          echo page_enabled($argv[1], ["fsState" => $argv[2]], $argv[3]) ? "show" : "hide";' "$c" "$1" "$R" 2>/dev/null | tr -d ' '   # evalContent.php itself prints trailing blanks after its closing tag
}
[ "$(cond Started 'SHOW_TAB="yes"')" = show ] && [ "$(cond Stopped 'SHOW_TAB="yes"')" = hide ] && [ "$(cond Started 'SHOW_TAB="no"')" = hide ] \
  && ok "header tab: shown only when SHOW_TAB=yes AND the array is Started" || bad "tab Cond: $(cond Started 'SHOW_TAB="yes"') $(cond Stopped 'SHOW_TAB="yes"') $(cond Started 'SHOW_TAB="no"')"
exit $fail
