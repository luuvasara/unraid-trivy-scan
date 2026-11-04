#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# render-test.sh - render the pages in a local harness (php -S on 127.0.0.1, tests/render/router.php) with Unraid's
# own stylesheets (fetch-webgui.sh) and check them with standalone headless Chrome (no Playwright, no MCP):
#   hostile  every string in the report, settings file and state files carries markup/script payloads: the raw
#            HTML of the server-rendered pages and Chrome's DOM after the scripts ran must show each MARK exactly
#            once-escaped, no payload may execute (data-pwned on <html>), no javascript: link may appear
#   demo     screenshots, light (white theme) and dark (black theme): report, expanded CVE row, settings, dashboard
#   empty    no report yet (empty state)
#   action   include/action.php: GET refused, missing/wrong csrf_token refused, unknown action refused, start ok
# DEMO_REPORT=<report.json> uses that report for the demo screenshots (e.g. one from tests/e2e.sh); default is the
# aggregated tests/fixtures/basic. Screenshots: docs/screenshots/ (SHOTS=<dir> to change).
set -uo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-cve-lens
W=$HERE/tests/.work/render; rm -rf "$W"; mkdir -p "$W"
SHOTS=${SHOTS:-$HERE/docs/screenshots}; mkdir -p "$SHOTS"
CHROME=${CHROME:-google-chrome}
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
"$HERE/tests/render/fetch-webgui.sh" >/dev/null || { echo "FAIL cannot fetch webGui styles"; exit 1; }

PIDS=()
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

scenario() {   # scenario <name> <port> <theme>: webroot + env + php -S in the background
  local name=$1 port=$2 theme=$3
  local d=$W/$name
  mkdir -p "$d/webroot/plugins" "$d/data/report" "$d/run"
  ln -sfn "$HERE/tests/.work/webgui/webGui" "$d/webroot/webGui"
  ln -sfn "$P" "$d/webroot/plugins/unraid-cve-lens"
  [ -f "$d/varini" ] || printf 'csrf_token="0123456789ABCDEF"\n' >"$d/varini"
  printf '#!/bin/sh\necho "$*" >>%s/stub.log\ncase "$1" in image) echo "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c" ;; grype-image) echo "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea" ;; *) echo "scan started" ;; esac\n' "$d" >"$d/stub"
  chmod 755 "$d/stub"
  env THEME="$theme" WEBROOT="$d/webroot" UTS_CFG="$d/cfg" UTS_DATA="$d/data" UTS_RUN="$d/run" UTS_VARINI="$d/varini" \
      UTS_SCRIPT="$d/stub" TZ=UTC php -S "127.0.0.1:$port" -t "$d/webroot" "$HERE/tests/render/router.php" >"$d/php.log" 2>&1 &
  PIDS+=($!)
}
wait_up() { local _; for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$1/Dashboard" && return 0; sleep 0.1; done; return 1; }
chrome() { TZ=UTC "$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check --hide-scrollbars \
             --user-data-dir="$W/chrome-profile" --virtual-time-budget=10000 "$@" 2>/dev/null; }
dom()  { chrome --dump-dom "$1"; }
shot() { chrome --window-size="$2" --screenshot="$3" "$1" >/dev/null && [ -s "$3" ]; }

# ---------------------------------------------------------------- hostile
H=$W/hostile; mkdir -p "$H"
python3 -I "$HERE/tests/fixtures/hostile.py" "$H"
php "$P/include/aggregate.php" "$H/work" "$H/data/report/report.json" "registry=yes" "trivy=0.76.1<script>x</script>" >/dev/null \
  || bad "aggregate hostile"
bash -c 'exec -a cve-lens-harness sleep 300' & PIDS+=($!); echo $! >"$H/run/pid"    # makes the scan look "running"
scenario hostile 18731 black
wait_up 18731 || { echo "FAIL harness did not start: $(cat "$H/php.log")"; exit 1; }
B=http://127.0.0.1:18731
check_text() {   # check_text <label> <html> <mark...>: each MARK once-escaped, never raw, never double-escaped
  local label=$1 html=$2 m; shift 2
  for m in "$@"; do
    if grep -qF "&lt;b&gt;MARK$m&lt;/b&gt;&amp;amp;" <<<"$html" && ! grep -qF "<b>MARK$m</b>" <<<"$html" \
       && ! grep -qF "&amp;lt;b&amp;gt;MARK$m" <<<"$html"; then ok "$label: MARK$m shown as text, escaped once"
    else bad "$label: MARK$m not escaped exactly once"; fi
  done
}
no_payload() {   # no_payload <label> <html>
  if grep -qE '<img src=x onerror|<svg/onload|<script>document|data-pwned=|href="javascript:' <<<"$2"; then
    bad "$1: payload present unescaped or executed: $(grep -oE '.{40}(<img src=x onerror|<svg/onload|<script>document|data-pwned=|href="javascript:).{20}' <<<"$2" | head -2)"
  else ok "$1: no payload unescaped, nothing executed"; fi
}
RAW=$(curl -s "$B/?tab=2"); no_payload "settings raw HTML" "$RAW"; check_text "settings raw HTML" "$RAW" cfg
grep -q 'PATH' <<<"$RAW" && bad "settings shows the unknown PATH key" || ok "settings ignores unknown keys from the file"
RAW=$(curl -s "$B/Dashboard"); no_payload "dashboard raw HTML" "$RAW"; check_text "dashboard raw HTML" "$RAW" lastrun
grep -q 'Scanning: 1 of 2' <<<"$RAW" && ok "dashboard shows scan progress" || bad "dashboard progress"
DOM=$(dom "$B/?tab=1#open=CVE-2024-0101"); no_payload "report DOM (row expanded)" "$DOM"
check_text "report DOM" "$DOM" title1 pkg1 target image cont reason failedimg warn current regfail os ospath kernel ospkg
grep -q 'Unraid OS 7.3.4: OS packages, not CVE-matched (2)' <<<"$DOM" && ok "report: OS package list shown, labelled not CVE-matched" || bad "report: OS package list" 
grep -q 'https://nvd.nist.gov/vuln/detail/CVE-2024-0100' <<<"$(dom "$B/?tab=1#open=CVE-2024-0100")" \
  && ok "report: javascript: advisory URL replaced by the NVD link" || bad "report: CVE-2024-0100 link"
grep -q 'x.test' <<<"$DOM" && bad "report: URL with a quote was kept" || ok "report: advisory URL with a quote dropped"
DOM=$(dom "$B/?tab=1"); no_payload "report DOM (default filters)" "$DOM"
grep -q '>CVE-2024-0101<' <<<"$DOM" && ! grep -q '>CVE-2024-0100<' <<<"$DOM" && grep -q 'without a fix hidden' <<<"$DOM" \
  && ok "report default filters: fixable CVE shown, CVE without a fix hidden (and counted)" || bad "report default filters"
SJ=$(curl -s "$B/plugins/unraid-cve-lens/include/status.php")
php -r '$j=json_decode($argv[1],true); exit(($j["running"]??false)===true && $j["done"]===1 && $j["total"]===2 ? 0 : 1);' "$SJ" \
  && ok "status.php: running, 1 of 2" || bad "status.php: $SJ"
grep -q '<script\|<img' <<<"$SJ" && bad "status.php emits raw markup" || ok "status.php JSON has markup hex-escaped"
shot "$B/?tab=1#open=CVE-2024-0101" 1400,1300 "$W/hostile-report.png" && ok "hostile report screenshot (tests/.work)" || bad "hostile screenshot"

# ---------------------------------------------------------------- action endpoint
A=$B/plugins/unraid-cve-lens/include/action.php
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code "$A")" = 405 ] && ok "action.php: GET refused (405)" || bad "action.php GET"
[ "$(code -d action=start "$A")" = 403 ] && ok "action.php: no csrf_token refused (403)" || bad "action.php no token"
[ "$(code -d action=start -d csrf_token=wrong "$A")" = 403 ] && ok "action.php: wrong csrf_token refused (403)" || bad "action.php wrong token"
[ "$(code -d 'action=start;id' -d csrf_token=0123456789ABCDEF "$A")" = 400 ] && ok "action.php: unknown action refused (400)" || bad "action.php unknown action"
[ "$(code -d 'action[]=start' -d csrf_token=0123456789ABCDEF "$A")" = 400 ] && ok "action.php: array action refused (400)" || bad "action.php array"
: >"$H/stub.log"
[ "$(code -d action=start -d csrf_token=0123456789ABCDEF "$A")" = 200 ] && [ "$(cat "$H/stub.log")" = start ] \
  && ok "action.php: start runs 'cve-lens start' with a fixed argument" || bad "action.php start: $(cat "$H/stub.log")"

# ---------------------------------------------------------------- demo screenshots (light + dark)
for theme in white black; do
  port=$([ $theme = white ] && echo 18732 || echo 18733)
  D=$W/demo-$theme; mkdir -p "$D/data/report" "$D/data/cache/db"
  if [ -n "${DEMO_REPORT:-}" ]; then cp "$DEMO_REPORT" "$D/data/report/report.json"
  else php "$P/include/aggregate.php" "$HERE/tests/fixtures/basic" "$D/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" >/dev/null; fi
  printf 'result=ok\nended=%s\nmessage=%s\n' "$(php -r 'echo json_decode(file_get_contents($argv[1]),true)["generated"];' "$D/data/report/report.json")" \
    "$(php -r '$r=json_decode(file_get_contents($argv[1]),true); echo $r["summary"]["images"]," image(s)",($r["summary"]["os"]??"off")!=="off"?" and the Unraid OS":""," scanned, ",$r["summary"]["failed"]," failed";' "$D/data/report/report.json")" \
    >"$D/data/report/last-run"
  printf 'SCHEDULE="30 3 * * 0"\nSCOPE="running"\nREGISTRY_CHECK="yes"\n' >"$D/cfg"
  scenario "demo-$theme" "$port" "$theme"; wait_up "$port" || bad "demo harness $theme"
  U=http://127.0.0.1:$port
  label=$([ $theme = white ] && echo light || echo dark)
  OPEN=$(php -r '$r=json_decode(file_get_contents($argv[1]),true); foreach ($r["cves"] as $c) if ($c["fix"]!=="none") { echo $c["id"]; break; }' "$D/data/report/report.json")
  shot "$U/?tab=1" 1400,1500 "$SHOTS/report-$label.png" && ok "screenshot report-$label.png" || bad "screenshot report $label"
  shot "$U/?tab=1#open=$OPEN" 1400,1000 "$SHOTS/report-expanded-$label.png" && ok "screenshot report-expanded-$label.png ($OPEN)" || bad "screenshot expanded $label"
  OSOPEN=$(php -r '$r=json_decode(file_get_contents($argv[1]),true); $os=null; foreach ($r["images"] as $i=>$im) if (($im["kind"]??"")==="os") $os=$i;
    if ($os!==null) foreach ($r["cves"] as $c) foreach ($c["affected"] as $a) if ($a["img"]===$os && $c["fix"]!=="none") { echo $c["id"]; exit; }' "$D/data/report/report.json")
  if [ -n "$OSOPEN" ]; then
    shot "$U/?tab=1#open=$OSOPEN&packages" 1400,1700 "$SHOTS/report-os-$label.png" && ok "screenshot report-os-$label.png ($OSOPEN, OS package list open)" || bad "screenshot os $label"
  else echo "note: the demo report has no Unraid OS findings, no report-os-$label.png"; fi
  SD=$(dom "$U/?tab=2" | tr -d '\n' | grep -o '<dl class="uts-about">.*</dl>')   # the visible About list (screenshots go into docs/)
  grep -q '/mnt/user/appdata/unraid-cve-lens' <<<"$SD" && ! grep -qF "$HERE" <<<"$SD" && grep -q 'anchore/grype:' <<<"$SD" \
    && ok "settings About shows the default data directory and the Grype image, not this checkout's path ($theme)" || bad "settings About: $(head -c 300 <<<"$SD")"
  shot "$U/?tab=2" 1400,1700 "$SHOTS/settings-$label.png" && ok "screenshot settings-$label.png" || bad "screenshot settings $label"
  shot "$U/Dashboard" 560,330 "$SHOTS/tile-$label.png" && ok "screenshot tile-$label.png" || bad "screenshot tile $label"
  DOM=$(dom "$U/?tab=1"); grep -q 'uts-cves' <<<"$DOM" && grep -q 'class="uts-row' <<<"$DOM" && ok "demo report renders rows ($theme)" || bad "demo report rows ($theme)"
done

# ---------------------------------------------------------------- empty state
E=$W/empty; mkdir -p "$E"; scenario empty 18734 black; wait_up 18734 || bad "empty harness"
DOM=$(dom "http://127.0.0.1:18734/?tab=1")
grep -q 'No report yet' <<<"$DOM" && ok "empty state shown without a report" || bad "empty state"
shot "http://127.0.0.1:18734/?tab=1" 1400,600 "$SHOTS/empty-dark.png" && ok "screenshot empty-dark.png" || bad "screenshot empty"
grep -qi 'fatal\|error\|warning:\|deprecated\|notice:' "$W"/*/php.log && { bad "PHP warnings in the harness logs:"; grep -hi 'fatal\|error\|warning:\|deprecated\|notice:' "$W"/*/php.log | head -5; } || ok "no PHP errors, warnings or notices while rendering"
exit $fail
