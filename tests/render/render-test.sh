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
#   scanners who found what: one card per scanner, Found by tags and filter
#   webgui612 the pages and the dashboard tile in the Unraid 6.12.15 webGui layout (stylesheets and DashStats.page
#            of that release): the tile uses the older header markup there
#   progress the run panel: a fake running scan (steps, download sample, log), the idle summary, "View log" (Unraid's
#            openTerminal when present, else include/log.php), and log.php itself
# RENDER_PORT_BASE=<port> (default 18731): the harness listens on this port and the next 20, so runs in several
# checkouts at the same time can use separate ranges.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-cve-lens
W=$HERE/tests/.work/render; rm -rf "$W"; mkdir -p "$W"
SHOTS=${SHOTS:-$HERE/docs/screenshots}; mkdir -p "$SHOTS"
CHROME=${CHROME:-google-chrome}
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
PB=${RENDER_PORT_BASE:-18731}
[[ $PB =~ ^[0-9]{4,5}$ ]] && [ "$PB" -ge 1024 ] && [ "$PB" -le 65000 ] || { echo "FAIL RENDER_PORT_BASE must be a port number 1024-65000"; exit 1; }
PORT_HOSTILE=$PB PORT_DEMO_LIGHT=$((PB + 1)) PORT_DEMO_DARK=$((PB + 2)) PORT_EMPTY=$((PB + 3)) PORT_EXPLOIT=$((PB + 4))
PORT_IGNORE_LIGHT=$((PB + 5)) PORT_IGNORE_DARK=$((PB + 6))
PORT_PROG_LIGHT=$((PB + 7)) PORT_PROG_DARK=$((PB + 8)) PORT_PROG_IDLE=$((PB + 9))
PORT_SCAN_LIGHT=$((PB + 10)) PORT_SCAN_DARK=$((PB + 11)) PORT_612_LIGHT=$((PB + 12)) PORT_612_DARK=$((PB + 13))
PORT_IMG_LIGHT=$((PB + 14)) PORT_IMG_DARK=$((PB + 15)) PORT_IMG_612=$((PB + 16)) PORT_IMG_NODB=$((PB + 17)) PORT_IMG_GRAY=$((PB + 18)) PORT_IMG_AZURE=$((PB + 19)) PORT_IMG_COMPOSE=$((PB + 20))
"$HERE/tests/render/fetch-webgui.sh" >/dev/null || { echo "FAIL cannot fetch webGui styles"; exit 1; }
"$HERE/tests/render/fetch-webgui.sh" 6.12 >/dev/null || { echo "FAIL cannot fetch the 6.12.15 webGui styles"; exit 1; }

PIDS=()
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

scenario() {   # scenario <name> <port> <theme> [6.12]: webroot + env + php -S in the background
  local name=$1 port=$2 theme=$3 gui=${4:-}
  local wg=$HERE/tests/.work/webgui${gui:+-$gui}
  local d=$W/$name
  # a server already on this port (another checkout running the suite) would answer for this one
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/"; then echo "FAIL port $port is in use (set RENDER_PORT_BASE)"; exit 1; fi
  mkdir -p "$d/webroot/plugins" "$d/data/report" "$d/run"
  ln -sfn "$wg/webGui" "$d/webroot/webGui"
  ln -sfn "$wg/dynamix" "$d/webroot/plugins/dynamix"     # DashStats.page of that webGui (the tile header reads it)
  ln -sfn "$P" "$d/webroot/plugins/unraid-cve-lens"
  [ -f "$d/varini" ] || printf 'csrf_token="0123456789ABCDEF"\n' >"$d/varini"
  printf '#!/bin/sh\necho "$*" >>%s/stub.log\ncase "$1" in scan-image-cmd) exec env UTS_DATA=%s/data UTS_CFG=%s/cfg bash %s/scripts/cve-lens "$@" ;; image) echo "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c" ;; grype-image) echo "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea" ;; *) echo "scan started" ;; esac\n' "$d" "$d" "$d" "$P" >"$d/stub"
  chmod 755 "$d/stub"
  env THEME="$theme" WEBGUI="$gui" WEBROOT="$d/webroot" UTS_CFG="$d/cfg" UTS_DATA="$d/data" UTS_RUN="$d/run" UTS_VARINI="$d/varini" UTS_LOG="$d/log" \
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
scenario hostile "$PORT_HOSTILE" black
wait_up "$PORT_HOSTILE" || { echo "FAIL harness did not start: $(cat "$H/php.log")"; exit 1; }
B=http://127.0.0.1:$PORT_HOSTILE
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
check_text "report DOM" "$DOM" title1 pkg1 target image cont reason failedimg warn current regfail os ospath kernel ospkg pname pkgerr
grep -q 'uts-scanner-ver">0.76.1&lt;script&gt;x&lt;/script&gt;<' <<<"$DOM" && ok "report: the Trivy version in the Scanners overview is text" || bad "report: hostile Trivy version in the Scanners overview"
grep -q 'uts-scanner-cpe uts-scanner-state-failed' <<<"$DOM" && ok "report: failed OS package match shown as a failed Grype card" || bad "report: Grype card state for a failed match"
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
  port=$([ $theme = white ] && echo $PORT_DEMO_LIGHT || echo $PORT_DEMO_DARK)
  D=$W/demo-$theme; mkdir -p "$D/data/report" "$D/data/cache/db"
  if [ -n "${DEMO_REPORT:-}" ]; then cp "$DEMO_REPORT" "$D/data/report/report.json"
  else
    # two runs, so the page shows "since the last scan" and a trend: an older run without CVE-2024-0002, then the fixture;
    # a few earlier history lines (growing counts) give the trend its shape
    cp -r "$HERE/tests/fixtures/basic" "$D/older"
    python3 -I - "$D/older/local/1.json" "$D/data/report/history.jsonl" <<'PYEOF'
import json, sys
j = json.load(open(sys.argv[1]))
for r in j["Results"]:
    r["Vulnerabilities"] = [v for v in r.get("Vulnerabilities", []) if v.get("VulnerabilityID") != "CVE-2024-0002"]
json.dump(j, open(sys.argv[1], "w"))
with open(sys.argv[2], "w") as h:
    for i in range(10):
        n = 2 + (i * 7) % 5
        h.write(json.dumps({"generated": 1700000000 + i * 86400, "total": n, "fixable": n - 1, "by_severity": {"CRITICAL": i % 3}, "images": 2, "failed": 0, "os": "off", "os_cves": 0, "ids_sha1": "0" * 40}) + "\n")
PYEOF
    php "$P/include/aggregate.php" "$D/older" "$D/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" >/dev/null
    php "$P/include/aggregate.php" "$HERE/tests/fixtures/basic" "$D/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" >/dev/null
  fi
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
  DOM=$(dom "$U/?tab=1")
  if [ -z "${DEMO_REPORT:-}" ]; then   # these counts are the fixture's; a DEMO_REPORT from e2e has other containers
  grep -q 'Container risk (4 containers): 1 privileged, 2 with the Docker socket, 1 on the host network, 1 with the host PID namespace, 2 with SYS_ADMIN or ALL capabilities, 2 with ports on all interfaces' <<<"$DOM" \
    && ok "container risk summary line ($theme)" || bad "container risk summary ($theme): $(grep -o 'Container risk ([^<]*' <<<"$DOM" | head -1)"
  grep -q 'Docker socket: </strong>The container can control Docker' <<<"$DOM" && ok "container risk column help shown ($theme)" || bad "container risk help ($theme)"
  grep -q '<details class="uts-images uts-posture">' <<<"$DOM" && ok "container risk section is collapsed by default ($theme)" || bad "container risk not collapsed ($theme)"
  else grep -q 'Container risk (' <<<"$DOM" && ok "container risk summary present in the e2e report ($theme)" || bad "container risk summary missing ($theme)"; fi
  shot "$U/?tab=1#posture" 1500,1500 "$SHOTS/posture-$label.png" && ok "screenshot posture-$label.png" || bad "screenshot posture $label"
  SD=$(dom "$U/?tab=2" | tr -d '\n' | grep -o '<dl class="uts-about">.*</dl>')   # the visible About list (screenshots go into docs/)
  grep -q '/mnt/user/appdata/unraid-cve-lens' <<<"$SD" && ! grep -qF "$HERE" <<<"$SD" && grep -q 'anchore/grype:' <<<"$SD" \
    && ok "settings About shows the default data directory and the Grype image, not this checkout's path ($theme)" || bad "settings About: $(head -c 300 <<<"$SD")"
  shot "$U/?tab=2" 1400,1700 "$SHOTS/settings-$label.png" && ok "screenshot settings-$label.png" || bad "screenshot settings $label"
  shot "$U/Dashboard" 560,330 "$SHOTS/tile-$label.png" && ok "screenshot tile-$label.png" || bad "screenshot tile $label"
  DOM=$(dom "$U/?tab=1"); grep -q 'uts-cves' <<<"$DOM" && grep -q 'class="uts-row' <<<"$DOM" && ok "demo report renders rows ($theme)" || bad "demo report rows ($theme)"
  if [ -z "${DEMO_REPORT:-}" ]; then
    grep -q 'Since the last scan' <<<"$DOM" && grep -q '+1 new, ' <<<"$DOM" && grep -q 'class="uts-spark"' <<<"$DOM" && grep -q 'Download CSV (current view)' <<<"$DOM" \
      && ok "demo report ($theme): changes line, trend sparkline and export buttons rendered" || bad "demo report ($theme): changes/trend/export missing"
  fi
done

# ---------------------------------------------------------------- exploit signals and end-of-life base
# basic fixture + KEV/EPSS fixture files + one image flagged end of life (Metadata.OS.EOSL)
X=$W/exploit; mkdir -p "$X/data/report" "$X/work"; cp -r "$HERE/tests/fixtures/basic/." "$X/work/"
php -r '$f=$argv[1]; $j=json_decode(file_get_contents($f),true); $j["Metadata"]["OS"]["EOSL"]=true; file_put_contents($f, json_encode($j));' "$X/work/local/1.json"
php "$P/include/aggregate.php" "$X/work" "$X/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" "exploit=$HERE/tests/fixtures/exploit" >/dev/null || bad "aggregate exploit demo"
printf 'result=ok\nended=%s\nmessage=3 image(s) scanned, 1 failed\n' "$(date +%s)" >"$X/data/report/last-run"
: >"$X/cfg"; scenario exploit "$PORT_EXPLOIT" white; wait_up "$PORT_EXPLOIT" || bad "exploit harness"
XU="http://127.0.0.1:$PORT_EXPLOIT/?tab=1"
DOM=$(dom "$XU")
grep -q 'uts-kev-badge' <<<"$DOM" && grep -q 'Known exploited' <<<"$DOM" && ok "report shows the Known exploited badge" || bad "no Known exploited badge"
grep -q '>83%<' <<<"$DOM" && grep -q 'EPSS' <<<"$DOM" && ok "report shows the EPSS column (CVE-2024-0001: 83%)" || bad "no EPSS value"
grep -q 'id="uts-exp"' <<<"$DOM" && grep -q 'Exploited / likely (KEV or EPSS' <<<"$DOM" && ok "report has the Exploit signal filter" || bad "no exploit filter"
grep -q 'uts-eol-badge' <<<"$DOM" && grep -q 'End of life base' <<<"$DOM" && grep -q 'no more security fixes' <<<"$DOM" && ok "scanned-targets table shows the End of life base badge with its help text" || bad "no end-of-life badge"
grep -q 'uts-card-kev' <<<"$DOM" && ok "summary has the Known exploited count" || bad "no KEV summary card"
shot "$XU" 1400,1500 "$SHOTS/report-exploit-light.png" && ok "screenshot report-exploit-light.png" || bad "screenshot exploit"
shot "${XU}#images&open=CVE-2024-0001" 1400,1250 "$SHOTS/report-exploit-expanded-light.png" && ok "screenshot report-exploit-expanded-light.png (scanned images open, one CVE expanded)" || bad "screenshot exploit expanded"

# ---------------------------------------------------------------- ignore list: Ignored section, expired/invalid notices, the form
for theme in white black; do
  port=$([ $theme = white ] && echo $PORT_IGNORE_LIGHT || echo $PORT_IGNORE_DARK); label=$([ $theme = white ] && echo light || echo dark)
  I=$W/ignore-$theme; mkdir -p "$I/data/report" "$I/work"; cp -r "$HERE/tests/fixtures/basic/." "$I/work/"
  printf '# accepted risks\nCVE-2024-0002 example/web:1.2 until=2026-12-31 # only reachable from the LAN\nGHSA-abcd-efgh-ijkl * # false positive, jar is not loaded\nCVE-2024-0004 until=2026-01-01 # waiting for the vendor\nthis line is wrong\n' >"$I/work/ignore.txt"
  php "$P/include/aggregate.php" "$I/work" "$I/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" today=2026-11-03 >/dev/null || bad "aggregate ignore demo"
  printf 'result=ok\nended=%s\nmessage=2 image(s) scanned, 1 failed\n' "$(php -r 'echo json_decode(file_get_contents($argv[1]),true)["generated"];' "$I/data/report/report.json")" >"$I/data/report/last-run"
  printf 'SCOPE="running"\n' >"$I/cfg"
  scenario "ignore-$theme" "$port" "$theme"; wait_up "$port" || bad "ignore harness $theme"
  DOM=$(dom "http://127.0.0.1:$port/?tab=1"); no_payload "ignore report DOM ($theme)" "$DOM"
  grep -q '2 finding(s) ignored: not counted, never notified' <<<"$DOM" && grep -q '1 expired ignore entry' <<<"$DOM" && grep -q '1 invalid line(s) in ignore.txt' <<<"$DOM" && grep -q 'line 5: does not start with' <<<"$DOM" \
    && ok "ignore ($theme): Ignored section, expired entry and invalid line shown" || bad "ignore ($theme): sections missing"
  grep -q 'Stop ignoring' <<<"$DOM" && ok "ignore ($theme): 'Stop ignoring' buttons present" || bad "ignore ($theme): no Stop ignoring"
  DOM=$(dom "http://127.0.0.1:$port/?tab=1#open=CVE-2024-0003&ignore")
  grep -q 'Applies to' <<<"$DOM" && grep -q 'This image: example/web:1.2' <<<"$DOM" && grep -q 'All images and the OS' <<<"$DOM" && grep -q 'Until (optional)' <<<"$DOM" \
    && ok "ignore ($theme): the form offers this image / all images, reason and date" || bad "ignore ($theme): form fields"
  DOM=$(dom "http://127.0.0.1:$port/?tab=1#open=CVE-2024-0003"); grep -q '>Ignore…<' <<<"$DOM" && ok "ignore ($theme): 'Ignore…' button in the expanded row" || bad "ignore ($theme): no Ignore button"
  shot "http://127.0.0.1:$port/?tab=1#open=CVE-2024-0003&ignore" 1400,1500 "$SHOTS/ignore-form-$label.png" && ok "screenshot ignore-form-$label.png" || bad "screenshot ignore form $label"
  shot "http://127.0.0.1:$port/?tab=1" 1400,1300 "$SHOTS/ignore-list-$label.png" && ok "screenshot ignore-list-$label.png" || bad "screenshot ignore list $label"
done

# ---------------------------------------------------------------- run progress panel and "View log"
# A scan that "runs" (a live process named like the script, as in hostile): $RUN/steps with every state, a download
# sample, the progress line and a log with markup in it. Times are relative to now, so durations and the estimate are known.
NOW=$(date +%s)
prog_state() {   # prog_state <dir>
  local d=$1 t=$NOW
  mkdir -p "$d/run" "$d/data/report"
  cp "$HERE/tests/.work/render/demo-white/data/report/report.json" "$d/data/report/report.json" 2>/dev/null
  printf '%s\n' "id=$((t - 754))-4242" 'mode=scan' "started=$((t - 754))" \
    "step1=pull-trivy|skipped|$((t - 754))|$((t - 754))|0|0|0|Scanner image (Trivy)|already present" \
    "step2=db-trivy|done|$((t - 754))|$((t - 500))|0|0|812000000|Vulnerability database|" \
    "step3=db-java|failed|$((t - 500))|$((t - 470))|0|0|0|Java database|FATAL failed to download artifact" \
    "step4=db-grype|running|$((t - 470))|0|0|0|0|OS package database (Grype)|" \
    "step5=scan|waiting|0|0|0|0|0|Container image scans|" \
    "step6=os|waiting|0|0|0|0|0|Unraid OS scan|" "step7=report|waiting|0|0|0|0|0|Report|" >"$d/run/steps"
  printf 'step=db-grype\nbytes=412000000\nrate=3100000\nt=%s\n' "$t" >"$d/run/dl"
  printf 'phase=db\ndone=0\ntotal=0\ncurrent=OS package database (Grype)\n' >"$d/run/progress"
  printf '%s\n' 'line from an older run' "2026-11-04 10:00:00 scan $((t - 754))-4242 started (scope=running)" \
    '2026-11-04 10:00:01 updating the vulnerability DB' '2026-11-04 10:04:15 WARNING: Java DB update failed: FATAL failed to download artifact' \
    '2026-11-04 10:04:45 updating the Grype DB <b>MARKlog</b>&amp;<img src=x onerror=document.documentElement.setAttribute("data-pwned",1)>' >"$d/log"
  bash -c 'exec -a cve-lens-harness sleep 300' & PIDS+=($!); echo $! >"$d/run/pid"
}
for theme in white black; do
  port=$([ $theme = white ] && echo $PORT_PROG_LIGHT || echo $PORT_PROG_DARK); label=$([ $theme = white ] && echo light || echo dark)
  G=$W/progress-$theme; prog_state "$G"
  # the second theme: the image scan step running, 5 of 14 done after 300 s -> 60 s per image, 9 left -> about 9 min
  # (a few seconds pass between writing the files and the page load, hence the ranges in the checks)
  if [ $theme = black ]; then
    sed -i "s/^step4=db-grype|running|.*/step4=db-grype|done|$((NOW - 470))|$((NOW - 330))|0|0|431000000|OS package database (Grype)|/; s/^step5=scan|waiting|.*/step5=scan|running|$((NOW - 300))|0|5|14|0|Container image scans|/" "$G/run/steps"
    printf 'phase=scan\ndone=5\ntotal=16\ncurrent=example/web:1.2\n' >"$G/run/progress"; rm -f "$G/run/dl"
  fi
  scenario "progress-$theme" "$port" "$theme"; wait_up "$port" || bad "progress harness $theme"
  U=http://127.0.0.1:$port
  DOM=$(dom "$U/?tab=1"); no_payload "progress panel DOM ($theme)" "$DOM"
  check_text "progress panel DOM ($theme)" "$DOM" log
  grep -q '<details class="uts-run uts-run-running" id="uts-run" open=""' <<<"$DOM" && ok "progress ($theme): panel shown and open while the scan runs" || bad "progress ($theme): panel not open: $(grep -o '<details class="uts-run[^>]*>' <<<"$DOM")"
  grep -q 'Vulnerability database</span><span class="uts-step-state">done</span><span class="uts-step-detail">4 min 14 s · 812 MB downloaded' <<<"$DOM" \
    && grep -q 'Java database</span><span class="uts-step-state">failed</span><span class="uts-step-detail">30 s · FATAL failed to download artifact' <<<"$DOM" \
    && grep -q 'Report</span><span class="uts-step-state">waiting' <<<"$DOM" && grep -q 'Scanner image (Trivy)</span><span class="uts-step-state">skipped</span><span class="uts-step-detail">already present' <<<"$DOM" \
    && ok "progress ($theme): ordered steps with state, duration, bytes and the failure reason" || bad "progress ($theme): step rows"
  if [ $theme = white ]; then
    grep -qE 'OS package database \(Grype\)</span><span class="uts-step-state">running</span><span class="uts-step-detail">7 min 5[0-9] s · 412 MB so far, 3.1 MB/s' <<<"$DOM" \
      && ok "progress: running download shows elapsed time, bytes so far and the rate" || bad "progress: download line: $(grep -o 'OS package database (Grype)</span>.\{0,160\}' <<<"$DOM" | head -1)"
    grep -qE 'Scan progress: step 4 of 7 \(OS package database \(Grype\)\), 12 min 3[4-9] s so far' <<<"$DOM" && ok "progress: summary line with the step number and total elapsed time" || bad "progress: summary: $(grep -o '<summary id="uts-run-sum">[^<]*' <<<"$DOM")"
  else
    grep -qE 'Container image scans</span><span class="uts-step-state">running</span><span class="uts-step-detail">5 min [0-9] s · 5 of 14, about 9 min [0-9]{1,2} s left · now: example/web:1.2' <<<"$DOM" \
      && ok "progress: image scan step shows n of m, the time left from the average per image and the current image" || bad "progress: scan line: $(grep -o 'Container image scans</span>.\{0,160\}' <<<"$DOM" | head -1)"
  fi
  grep -q 'Latest log lines' <<<"$DOM" && grep -q 'updating the vulnerability DB' <<<"$DOM" && ! grep -q 'line from an older run' <<<"$DOM" \
    && ok "progress ($theme): latest log lines of this run only" || bad "progress ($theme): log lines"
  [ "$(grep -o 'href="/plugins/unraid-cve-lens/include/log.php"' <<<"$DOM" | wc -l)" -ge 2 ] && ok "progress ($theme): View log in the status bar and in the panel" || bad "progress ($theme): View log links"
  sed -i '/MARKlog/d' "$G/log"   # the screenshot (docs) without the payload line
  shot "$U/?tab=1" 1400,900 "$SHOTS/progress-$label.png" && ok "screenshot progress-$label.png" || bad "screenshot progress $label"
done
# after the download: the database is unpacked on the disk (slow on a NAS); the panel shows that instead of a stalled 0 kB/s
printf 'step=db-grype\nbytes=210000000\nrate=0\nt=%s\nunpacked=620000000\nurate=3000000\nexpect=3100000000\n' "$NOW" >"$W/progress-white/run/dl"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_LIGHT/?tab=1")
grep -qE 'OS package database \(Grype\)</span><span class="uts-step-state">running</span><span class="uts-step-detail">[0-9]+ min [0-9]+ s · 210 MB downloaded · unpacking: 620 MB of about 3.10 GB, 3.0 MB/s, about 13 min [0-9]+ s left' <<<"$DOM" \
  && ok "progress: unpacking after the download shows bytes written of the expected size, rate and time left" || bad "progress: unpack line: $(grep -o 'OS package database (Grype)</span>.\{0,200\}' <<<"$DOM" | head -1)"
printf 'step=db-grype\nbytes=210000000\nrate=0\nt=%s\nunpacked=0\nurate=0\nexpect=3100000000\n' "$NOW" >"$W/progress-white/run/dl"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_LIGHT/?tab=1")
grep -q '210 MB downloaded, unpacking...' <<<"$DOM" && ok "progress: download finished, unpacking not yet measurable" || bad "progress: after-download line: $(grep -o 'OS package database (Grype)</span>.\{0,160\}' <<<"$DOM" | head -1)"
# a step without a measurable count that reads a multi-GB database says why it takes long
echo "step8=pkgmatch|running|$((NOW - 60))|0|0|0|0|OS package match (NVD)|" >>"$W/progress-white/run/steps"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_LIGHT/?tab=1")
grep -q 'OS package match (NVD)</span><span class="uts-step-state">running</span><span class="uts-step-detail">1 min [0-9]* s · Grype reads its database (about 3 GB); on a hard disk this takes several minutes' <<<"$DOM" \
  && ok "progress: the OS package match says why it takes minutes on a hard disk" || bad "progress: pkgmatch line: $(grep -o 'OS package match (NVD)</span>.\{0,200\}' <<<"$DOM" | head -1)"
# Unraid's log window: with openTerminal defined, every View log link calls it with the fixed arguments and does not navigate
DOM=$(dom "http://127.0.0.1:$PORT_PROG_LIGHT/?tab=1&fake_terminal=1")
[ "$(grep -o "data-term=\"[^\"]*\"" <<<"$DOM")" = 'data-term="[log|CVE Lens|unraid-cve-lens.log][log|CVE Lens|unraid-cve-lens.log]"' ] \
  && ok "View log calls openTerminal('log','CVE Lens','unraid-cve-lens.log') when the webGui has it (status bar and panel)" || bad "openTerminal call: $(grep -o 'data-term="[^"]*"' <<<"$DOM")"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_LIGHT/?tab=2&fake_terminal=1")
grep -q 'data-term="\[log|CVE Lens|unraid-cve-lens.log\]"' <<<"$DOM" && grep -q 'data-uts-log="">View log</a>' <<<"$DOM" && ok "settings About: View log link calls openTerminal" || bad "settings View log: $(grep -o 'data-term="[^"]*"' <<<"$DOM")"
# the fallback endpoint
echo '2026-11-04 10:04:45 updating the Grype DB <b>MARKlog</b>' >>"$W/progress-white/log"
LU=http://127.0.0.1:$PORT_PROG_LIGHT/plugins/unraid-cve-lens/include/log.php
HD=$(curl -s -D - -o "$W/log.txt" "$LU?file=/etc/passwd&n=99999")
grep -qi '^content-type: text/plain; charset=utf-8' <<<"$HD" && grep -qi '^x-content-type-options: nosniff' <<<"$HD" && grep -qi '^cache-control: no-store' <<<"$HD" \
  && ok "log.php: text/plain, nosniff, no-store" || bad "log.php headers: $HD"
grep -q 'updating the Grype DB <b>MARKlog' "$W/log.txt" && ! grep -q 'root:' "$W/log.txt" && [ "$(grep -c . "$W/log.txt")" -le 502 ] \
  && ok "log.php: the plugin's log as text, query parameters ignored" || bad "log.php body: $(head -c 300 "$W/log.txt")"
[ "$(code -X POST "$LU")" = 405 ] && ok "log.php: POST refused (405)" || bad "log.php POST"
# idle: the last run's summary from last-steps, closed by default, still with View log
I=$W/progress-idle; mkdir -p "$I/data/report"
cp "$HERE/tests/.work/render/demo-white/data/report/report.json" "$I/data/report/report.json"
printf 'result=failed\nended=%s\nmessage=building the report failed (exit 255), see the log\n' "$NOW" >"$I/data/report/last-run"
printf '%s\n' "id=$((NOW - 1500))-1" 'mode=scan' "started=$((NOW - 1500))" \
  "step1=db-trivy|done|$((NOW - 1500))|$((NOW - 1380))|0|0|90000000|Vulnerability database|" \
  "step2=scan|done|$((NOW - 1380))|$((NOW - 60))|14|14|0|Container image scans|14 image(s)" \
  "step3=report|failed|$((NOW - 60))|$((NOW - 1))|0|0|0|Report|exit 255" 'result=failed' "ended=$NOW" >"$I/data/report/last-steps"
scenario progress-idle "$PORT_PROG_IDLE" white; wait_up "$PORT_PROG_IDLE" || bad "progress idle harness"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_IDLE/?tab=1")
grep -q '<details class="uts-run uts-run-idle uts-run-failed" id="uts-run">' <<<"$DOM" && grep -qE 'Last scan: failed [0-9-]+ [0-9:]+, took 25 min 0 s' <<<"$DOM" \
  && grep -q 'Container image scans</span><span class="uts-step-state">done</span><span class="uts-step-detail">22 min 0 s · 14 of 14 · 14 image(s)' <<<"$DOM" \
  && grep -q 'href="/plugins/unraid-cve-lens/include/log.php"' <<<"$DOM" \
  && ok "idle: last run's summary (result, when, total and per-step durations), collapsed, with View log" || bad "idle panel: $(grep -o '<details class="uts-run[^>]*>.\{0,200\}' <<<"$DOM")"
php -r '$f=$argv[1]; $r=json_decode(file_get_contents($f),true); unset($r["exploit"]); file_put_contents($f, json_encode($r));' "$I/data/report/report.json"
DOM=$(dom "http://127.0.0.1:$PORT_PROG_IDLE/?tab=1")
grep -q 'Not in this report: it was made before exploit data was added' <<<"$DOM" && ! grep -q 'Off: setting .Exploit data' <<<"$DOM" \
  && ok "scanners: a report from before exploit data says so instead of 'Off: setting'" || bad "scanners: old report exploit card: $(grep -o 'uts-scanner-exploit.\{0,300\}' <<<"$DOM" | head -1)"
grep -q 'Last scan failed' <<<"$DOM" && ok "idle: the failure line in the status bar has View log next to it" || bad "idle: status line"
shot "http://127.0.0.1:$PORT_PROG_IDLE/?tab=1#" 1400,700 "$W/progress-idle-closed.png" || bad "idle screenshot"
# ---------------------------------------------------------------- scanners: who found what
# tests/fixtures/scanners: container images (Trivy), the Unraid OS's language packages (Trivy rootfs) and its own
# packages (Grype, NVD CPE match), plus KEV/EPSS. CVE-2024-0001 is in two images (Trivy) and in the OS's openssl (Grype).
for theme in white black; do
  port=$([ $theme = white ] && echo $PORT_SCAN_LIGHT || echo $PORT_SCAN_DARK); label=$([ $theme = white ] && echo light || echo dark)
  S=$W/scanners-$theme; mkdir -p "$S/data/report"
  php "$P/include/aggregate.php" "$HERE/tests/fixtures/scanners" "$S/data/report/report.json" registry=yes "trivy=0.76.1@sha256:x" "exploit=$HERE/tests/fixtures/exploit" >/dev/null || bad "aggregate scanners demo"
  printf 'result=ok\nended=%s\nmessage=2 image(s) and the Unraid OS scanned, 1 failed\n' "$(php -r 'echo json_decode(file_get_contents($argv[1]),true)["generated"];' "$S/data/report/report.json")" >"$S/data/report/last-run"
  printf 'SCOPE="running"\nREGISTRY_CHECK="yes"\n' >"$S/cfg"
  scenario "scanners-$theme" "$port" "$theme"; wait_up "$port" || bad "scanners harness $theme"
  SU="http://127.0.0.1:$port/?tab=1"
  DOM=$(dom "$SU"); no_payload "scanners report DOM ($theme)" "$DOM"
  CARDS=$(tr -d '\n' <<<"$DOM" | grep -o '<section class="uts-scanners".*</section>')
  grep -q 'Scanners: who found what' <<<"$CARDS" && grep -q 'uts-scanner-trivy uts-scanner-state-partial' <<<"$CARDS" && grep -q 'uts-scanner-cpe uts-scanner-state-ok' <<<"$CARDS" \
    && grep -q 'uts-scanner-exploit uts-scanner-state-ok' <<<"$CARDS" && ok "scanners ($theme): one card each for Trivy (partly: 1 image failed), Grype, exploit data" || bad "scanners ($theme): cards $(head -c 400 <<<"$CARDS")"
  grep -q '>0.76.1<' <<<"$CARDS" && grep -q '>v0.121.0<' <<<"$CARDS" && grep -q '2 of 3 container images (1 failed), the language packages inside the Unraid OS' <<<"$CARDS" \
    && grep -q '6 of 7 OS packages (those mapped to an NVD product); kernel not included' <<<"$CARDS" && grep -q 'built 2026-11-03' <<<"$CARDS" \
    && ok "scanners ($theme): versions, coverage (images, OS packages mapped) and database dates" || bad "scanners ($theme): coverage/version facts"
  grep -q '>8 CVEs</a>' <<<"$CARDS" && grep -q '>6 CVEs</a> counted; 2 matches not counted' <<<"$CARDS" && grep -q 'CISA list of 2030-01-02' <<<"$CARDS" && grep -q '3 CVEs known exploited' <<<"$CARDS" \
    && ok "scanners ($theme): CVEs per scanner (Trivy 8, Grype 6 + 2 not counted), KEV marks" || bad "scanners ($theme): counts"
  grep -q 'Cannot see: the Unraid OS.s own Slackware packages' <<<"$CARDS" && grep -q 'Cannot see: fixes backported without a version change' <<<"$CARDS" \
    && ok "scanners ($theme): each scanner says what it cannot see" || bad "scanners ($theme): limits"
  grep -q '1 CVE reported by both scanners' <<<"$CARDS" && ok "scanners ($theme): CVEs reported by both scanners counted" || bad "scanners ($theme): both line"
  grep -q 'id="uts-src"' <<<"$DOM" && grep -q '>Found by<' <<<"$DOM" && grep -q '<option value="cpe">Grype (NVD)</option>' <<<"$DOM" \
    && ok "scanners ($theme): Found by filter next to the other filters" || bad "scanners ($theme): no Found by filter"
  ROWS=$(tr -d '\n' <<<"$DOM" | grep -o '<table class="uts-table uts-cves">.*</table>')
  grep -q 'CVE-2024-0001</a>.*<td class="uts-srccell"><span class="uts-src uts-src-trivy"[^>]*>Trivy</span> <span class="uts-src uts-src-cpe"[^>]*>Grype · NVD</span></td>' <<<"$ROWS" \
    && ok "scanners ($theme): CVE-2024-0001 is one row with both tags" || bad "scanners ($theme): row tags of CVE-2024-0001"
  [ "$(grep -o 'class="uts-src uts-src-cpe"' <<<"$ROWS" | wc -l)" -ge 4 ] && ok "scanners ($theme): Grype tags on the OS package rows" || bad "scanners ($theme): Grype tags"
  DOM=$(dom "$SU#open=CVE-2024-0001")
  grep -q 'Reported by both scanners: <span class="uts-src uts-src-trivy"[^>]*>Trivy</span> in example/web:1.2, example/db:2 (running older image bbbbbbbbbbbb); <span class="uts-src uts-src-cpe"[^>]*>Grype · NVD</span> in Unraid OS 7.3.4.' <<<"$DOM" \
    && grep -q '<th scope="col">Found by</th>' <<<"$DOM" && ok "scanners ($theme): expanded row says where each scanner found it, Found by per finding" || bad "scanners ($theme): expanded row"
  DOM=$(dom "$SU#src=cpe"); ROWS=$(tr -d '\n' <<<"$DOM" | grep -o '<table class="uts-table uts-cves">.*</table>')
  grep -q '>CVE-2026-111497<' <<<"$ROWS" && grep -q '>CVE-2024-0001<' <<<"$ROWS" && ! grep -q '>CVE-2024-0002<' <<<"$ROWS" && ! grep -q '>CVE-2025-2000<' <<<"$ROWS" \
    && grep -q '<option value="cpe" selected="">' <<<"$DOM" && ok "scanners ($theme): Found by Grype keeps Grype's CVEs (and the shared one), drops Trivy-only ones" || bad "scanners ($theme): Found by filter result"
  DOM=$(dom "$SU#src=trivy"); ROWS=$(tr -d '\n' <<<"$DOM" | grep -o '<table class="uts-table uts-cves">.*</table>')
  grep -q '>CVE-2024-0002<' <<<"$ROWS" && ! grep -q '>CVE-2026-111497<' <<<"$ROWS" && ok "scanners ($theme): Found by Trivy drops Grype-only CVEs" || bad "scanners ($theme): Found by Trivy"
  shot "$SU" 1400,1250 "$SHOTS/scanners-$label.png" && ok "screenshot scanners-$label.png" || bad "screenshot scanners $label"
  shot "$SU#open=CVE-2024-0001" 1400,1250 "$SHOTS/scanners-expanded-$label.png" && ok "screenshot scanners-expanded-$label.png" || bad "screenshot scanners expanded $label"
  shot "$SU#src=cpe" 1400,1250 "$SHOTS/scanners-grype-$label.png" && ok "screenshot scanners-grype-$label.png" || bad "screenshot scanners grype $label"
done
# a report with Trivy only (no OS package match): no Found by filter or column, the Grype card says it is off
if [ -z "${DEMO_REPORT:-}" ]; then DOM=$(dom "http://127.0.0.1:$PORT_DEMO_LIGHT/?tab=1")
! grep -q 'id="uts-src"' <<<"$DOM" && ! grep -q 'uts-srccell' <<<"$DOM" && grep -q 'uts-scanner-cpe uts-scanner-state-off' <<<"$DOM" && grep -q 'Off because the Unraid OS is not scanned' <<<"$DOM" \
  && ok "Trivy-only report: no Found by filter or column, Grype card off with the reason" || bad "Trivy-only report: Found by shown or Grype card wrong"; fi

# ---------------------------------------------------------------- Unraid 6.12.15 webGui layout
# The tile header follows the server's own dashboard: tile-header* spans where DashStats.page uses them (webGui 7.2
# and later, the default harness above), the icon + div.section + control link of the stock 6.12-7.1 tiles otherwise.
DOM=$(dom "http://127.0.0.1:$PORT_DEMO_LIGHT/Dashboard")
grep -q "class=\"tile-header-main\"" <<<"$DOM" && ok "dashboard tile: tile-header markup with the current webGui" || bad "dashboard tile (current webGui): no tile-header"
for theme in white black; do
  port=$([ $theme = white ] && echo $PORT_612_LIGHT || echo $PORT_612_DARK); label=$([ $theme = white ] && echo light || echo dark)
  L=$W/w612-$theme; mkdir -p "$L/data/report"; cp -r "$W/demo-$theme/data/." "$L/data/"
  cp "$W/demo-$theme/cfg" "$L/cfg" 2>/dev/null || : >"$L/cfg"
  scenario "w612-$theme" "$port" "$theme" 6.12; wait_up "$port" || bad "6.12 harness $theme"
  U=http://127.0.0.1:$port
  RAW=$(curl -s "$U/Dashboard"); DOM=$(dom "$U/Dashboard")
  ! grep -q 'tile-header' <<<"$RAW" && grep -q "<i class='fa fa-shield f32'></i><div class='section'>Vulnerabilities<br><span>" <<<"$RAW" \
    && grep -q "fa-external-link control" <<<"$RAW" && ok "6.12 dashboard tile ($theme): stock 6.12 header markup, no tile-header" || bad "6.12 tile header ($theme): $(grep -o "<tr><td>.\{0,300\}" <<<"$RAW" | head -1)"
  grep -q 'uts-tile-sev' <<<"$DOM" && ok "6.12 dashboard tile ($theme): severity counts rendered" || bad "6.12 tile body ($theme)"
  shot "$U/Dashboard" 560,330 "$W/tile-612-$label.png" && ok "screenshot tile-612-$label.png (tests/.work/render)" || bad "screenshot tile 612 $label"
  for tab in 1 2; do
    DOM=$(dom "$U/?tab=$tab")
    if [ $tab = 1 ]; then grep -q 'class="uts-row' <<<"$DOM" && ok "6.12 report ($theme) renders rows" || bad "6.12 report rows ($theme)"
    else grep -q 'uts-about' <<<"$DOM" && ok "6.12 settings ($theme) render" || bad "6.12 settings ($theme)"; fi
    shot "$U/?tab=$tab" 1400,1500 "$W/page-612-$tab-$label.png" && ok "screenshot page-612-$tab-$label.png" || bad "screenshot 612 tab $tab $label"
  done
done

# ---------------------------------------------------------------- scan an image (its own tab)
# A stored result (hostile strings in the Trivy output, a bare image name), the command the page shows (from the script's
# own argument list), the explanation of wrong inputs (include/lib.php), the missing-database state, 7.x themes and 6.12.
img_scenario() {   # img_scenario <name> <port> <theme> [6.12]: a data dir with a database and one stored result
  local name=$1 port=$2 theme=$3 gui=${4:-} d=$W/$1 id=1793865483-1234
  mkdir -p "$d/data/cache/db" "$d/data/image-scan/$id"
  printf 'x' >"$d/data/cache/db/trivy.db"; printf '{"UpdatedAt":"2026-11-05T07:00:54.9Z","NextUpdate":"2026-11-06T07:00:54Z"}' >"$d/data/cache/db/metadata.json"
  : >"$d/cfg"
  local wk=$d/work; mkdir -p "$wk/local"; cp "$H/work/local/1.json" "$wk/local/1.json"
  printf '1\t\talpine\t\t0\t\t\t\n' >"$wk/images.tsv"; printf '1\tlocal\tok\t\n' >"$wk/results.tsv"; : >"$wk/warnings.txt"
  php "$P/include/aggregate.php" "$wk" "$d/data/image-scan/$id/report.json" "trivy=0.76.1@sha256:x" "cache=$d/data/cache" "exploit=$HERE/tests/fixtures/exploit" history=no imageref=alpine >/dev/null || bad "aggregate image result"
  printf 'ref=alpine\nfinished=1793865486\ncves=3\n' >"$d/data/image-scan/$id/meta"
  printf 'result=ok\nended=1793865486\nref=alpine\nid=%s\nmessage=3 CVE(s) found\n' "$id" >"$d/data/image-scan/last"
  UTS_DATA=$d/data UTS_CFG=$d/cfg UTS_PLUGIN_DIR=$P bash "$P/scripts/cve-lens" scan-image-cmd alpine >"$d/data/image-scan/$id/cmd" || bad "scan-image-cmd for the stored result"
  scenario "$name" "$port" "$theme" "$gui"; wait_up "$port" || bad "image harness $name"
}
for theme in white black; do
  port=$([ $theme = white ] && echo $PORT_IMG_LIGHT || echo $PORT_IMG_DARK); label=$([ $theme = white ] && echo light || echo dark)
  img_scenario "image-$theme" "$port" "$theme"
  U=http://127.0.0.1:$port
  RAW=$(curl -s "$U/?tab=3"); DOM=$(dom "$U/?tab=3#open=CVE-2024-0101")
  grep -q 'id="uts-i-imgref"' <<<"$RAW" && grep -q 'Scan an image' <<<"$(curl -s "$U/?tab=1")" && ok "image tab ($theme): the tab exists next to Report and Settings, the page has the input" || bad "image tab ($theme): input or tab"
  no_payload "image tab DOM ($theme)" "$DOM"; check_text "image result ($theme)" "$DOM" title1 pkg1 target
  for t in 'What to enter' 'How to find it' 'A Community Apps app' 'is an XML template, not an image' 'A compose file' 'build:' 'A GitHub project' 'A similarly named image can belong to someone else' 'the row <strong>Repository</strong>' 'choose <strong>Edit</strong>' '<strong>Advanced View</strong>' 'not part of an image scan'; do
    grep -qF "$t" <<<"$RAW" || bad "image tab ($theme): help text '$t' missing"
  done; ok "image tab ($theme): help names the four things, the CA Repository row, Docker tab Edit, compose image:, GitHub docs, and that Grype is not part of an image scan"
  [ "$(grep -o 'class="uts-ex"' <<<"$RAW" | wc -l)" = 4 ] && grep -q 'data-ref="postgres:17"' <<<"$RAW" && grep -q 'data-ref="lscr.io/linuxserver/sonarr:latest"' <<<"$RAW" && grep -q 'data-ref="ghcr.io/home-assistant/home-assistant:stable"' <<<"$RAW" && grep -q 'data-ref="alpine:3.20"' <<<"$RAW" \
    && ok "image tab ($theme): four examples (Docker Hub short name, lscr.io, ghcr.io, version tag) that fill the field" || bad "image tab ($theme): examples"
  grep -q 'Vulnerability database from 2026-11-05' <<<"$DOM" && ! grep -q 'id="uts-i-scan" disabled=""' <<<"$DOM" && ok "image tab ($theme): status shows the database date, Scan enabled" || bad "image tab ($theme): status: $(grep -o 'id="uts-i-status">[^<]*' <<<"$DOM")"
  grep -q '>Resolved as<' <<<"$DOM" && grep -q 'docker.io/library/alpine:latest' <<<"$DOM" && grep -q 'resolved as docker.io/library/alpine: the Docker Hub official image' <<<"$DOM" && grep -q 'No tag was given, so latest was scanned' <<<"$DOM" \
    && grep -q '>Digest scanned<' <<<"$DOM" && grep -q '>Vulnerability database<' <<<"$DOM" && ok "image result ($theme): resolved name, digest, database date and the warning for a bare name" || bad "image result ($theme): header: $(tr -d '\n' <<<"$DOM" | grep -o 'uts-imgfacts.\{0,600\}')"
  grep -q 'It says nothing about how an app is configured when you run it' <<<"$DOM" && ok "image result ($theme): coverage note" || bad "image result ($theme): coverage note"
  grep -q 'The command this scan ran' <<<"$DOM" && grep -q 'aquasec/trivy:0.76.1@sha256:790fd66d' <<<"$DOM" && grep -q -- '--image-src remote' <<<"$DOM" && grep -q 'Docker part' <<<"$DOM" && grep -q 'Trivy part' <<<"$DOM" && grep -q 'trivy image' <<<"$DOM" \
    && ! grep -q 'config.json' <<<"$DOM" && ok "image result ($theme): the command used, docker part and trivy part apart, pinned Trivy image" || bad "image result ($theme): command"
  grep -q 'uts-card-critical' <<<"$DOM" && ! grep -q 'Images scanned' <<<"$DOM" && ! grep -q 'Fixed in a newer image' <<<"$DOM" && ! grep -q 'class="uts-ignore-open"\|Ignore…' <<<"$DOM" && ok "image result ($theme): severity cards and the report table, without the full scan's image count, registry filter or ignore form" || bad "image result ($theme): leftovers of the full report"
  IU=$U/plugins/unraid-cve-lens/include/image.php
  J=$(curl -s "$IU?cmd=lscr.io%2Flinuxserver%2Fsonarr%3Alatest")
  php -r '$j=json_decode($argv[1],true); exit(end($j["trivy"])==="lscr.io/linuxserver/sonarr:latest" && prev($j["trivy"])==="--" && $j["image"]==="aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c" && in_array("--rm",$j["docker"]) && !in_array("/var/run/docker.sock",$j["docker"]) ? 0 : 1);' "$J" \
    && ok "image.php?cmd: the command for a typed name, from the script (pinned image, no Docker socket)" || bad "image.php?cmd: $J"
  for ex in postgres:17 ghcr.io/home-assistant/home-assistant:stable; do [ "$(code "$IU?cmd=$ex")" = 200 ] || bad "image.php?cmd=$ex not 200"; done
  [ "$(code "$IU?cmd=https%3A%2F%2Fgithub.com%2Fo%2Fr")" = 400 ] && curl -s "$IU?cmd=https%3A%2F%2Fgithub.com%2Fo%2Fr" | grep -q 'project page' && [ "$(code "$IU?cmd=%24%28id%29")" = 400 ] && [ "$(code "$IU?id=..%2F..%2Fetc")" = 404 ] && [ "$(code "$IU?id=1793865483-1234&cmd=1")" = 200 ] \
    && ok "image.php: a project page and \$(id) refused with a reason, a path in id refused, the stored command served" || bad "image.php refusals"
  shot "$U/?tab=3" 1400,2300 "$W/image-$label.png" && ok "screenshot image-$label.png (tests/.work/render: it shows the hostile fixture)" || bad "screenshot image $label"
done
# no database yet: plain words, no scan possible
mkdir -p "$W/image-nodb"; scenario image-nodb "$PORT_IMG_NODB" black; wait_up "$PORT_IMG_NODB" || bad "image no-db harness"
DOM=$(dom "http://127.0.0.1:$PORT_IMG_NODB/?tab=3")
grep -q 'The vulnerability database is not on this server yet. Run a first scan from Settings, CVE Lens' <<<"$DOM" && grep -q 'id="uts-i-scan" disabled=""' <<<"$DOM" && grep -q 'No image scanned yet' <<<"$DOM" \
  && ok "image tab without a database: says to run a first scan from Settings, Scan disabled, nothing downloaded" || bad "image tab no-db: $(grep -o 'id="uts-i-status">[^<]*' <<<"$DOM")"
# a failure that could not be written to the data directory (run/image-last) is on the page, not "Ready"
FD=$W/image-black
printf 'result=failed\nended=%s\nref=alpine:3.20\nid=\nmessage=cannot write to /x/image-scan (No medium found): check the appdata location\n' "$(date +%s)" >"$FD/run/image-last"
DOM=$(dom "http://127.0.0.1:$PORT_IMG_DARK/?tab=3"); rm -f "$FD/run/image-last"
grep -qE 'id="uts-i-status">Last image scan failed [^<]*\(alpine:3.20\): cannot write to /x/image-scan \(No medium found\)' <<<"$DOM" && ok "image tab: a failure kept in the run directory is shown" || bad "image tab, run directory failure: $(grep -o 'id="uts-i-status">[^<]*' <<<"$DOM")"
# after a failed or stopped scan the previous image's result is not under the message; it stays in the Earlier results list
grep -q 'id="uts-i-noresult">The scan of alpine:3.20 failed, so there is no result for it' <<<"$DOM" && ! grep -q '>Digest scanned<' <<<"$DOM" && ! grep -q 'uts-cves' <<<"$DOM" \
  && ok "image tab: a failed scan replaces the previous result" || bad "image tab, failed scan keeps the old result: $(grep -o 'id="uts-i-noresult"[^<]*' <<<"$DOM")"
grep -qE 'id="uts-i-imgprev"( class="[^"]*")?>' <<<"$DOM" && grep -q 'Choose an earlier result' <<<"$DOM" && ok "image tab: after a failed scan the earlier result can be chosen from the list" || bad "image tab: earlier results list missing after a failed scan"
printf 'result=failed\nended=%s\nref=sonarr\nid=\nmessage=the registry refused access\n' "$(date +%s)" >"$FD/run/image-last"
DOM=$(dom "http://127.0.0.1:$PORT_IMG_DARK/?tab=3")
grep -q 'id="uts-i-barehint"' <<<"$DOM" && grep -q 'resolved as docker.io/library/sonarr' <<<"$DOM" && grep -q 'for example lscr.io/linuxserver/sonarr' <<<"$DOM" && grep -q 'Enter the full image name' <<<"$DOM" \
  && ok "image tab: a failed bare name gets the hint to enter the full image name" || bad "image tab: no bare-name hint: $(grep -o 'id="uts-i-noresult"[^<]*' <<<"$DOM")"
printf 'result=failed\nended=%s\nref=lscr.io/linuxserver/sonarr:latest\nid=\nmessage=the registry refused access\n' "$(date +%s)" >"$FD/run/image-last"
DOM=$(dom "http://127.0.0.1:$PORT_IMG_DARK/?tab=3")
grep -q 'id="uts-i-noresult"' <<<"$DOM" && ! grep -q 'id="uts-i-barehint"' <<<"$DOM" && ok "image tab: a failed full image name gets no bare-name hint" || bad "image tab: bare-name hint on a full name"
printf 'result=stopped\nended=%s\nref=sonarr\nid=\nmessage=stopped\n' "$(date +%s)" >"$FD/run/image-last"
DOM=$(dom "http://127.0.0.1:$PORT_IMG_DARK/?tab=3"); rm -f "$FD/run/image-last"
grep -q 'The scan of sonarr was stopped, so there is no result for it' <<<"$DOM" && ! grep -q '>Digest scanned<' <<<"$DOM" && ! grep -q 'id="uts-i-barehint"' <<<"$DOM" \
  && ok "image tab: a stopped scan shows no old result and no bare-name hint" || bad "image tab, stopped scan: $(grep -o 'id="uts-i-noresult"[^<]*' <<<"$DOM")"
# The example buttons keep the case of the image name: Unraid's themes upper-case buttons, and upper case is not a valid image name
for t in "white:$PORT_IMG_LIGHT" "black:$PORT_IMG_DARK"; do
  DOM=$(dom "http://127.0.0.1:${t#*:}/?tab=3&probe=1"); x=$(grep -o 'data-ex="[^"]*"' <<<"$DOM")
  [[ $x == 'data-ex="none|ui-monospace|'* ]] && ok "example buttons (${t%%:*} theme): text-transform none, monospace ($x)" || bad "example buttons (${t%%:*}): $x"
done
for theme in gray azure; do
  port=$([ $theme = gray ] && echo $PORT_IMG_GRAY || echo $PORT_IMG_AZURE)
  img_scenario "image-$theme" "$port" "$theme"
  x=$(grep -o 'data-ex="[^"]*"' <<<"$(dom "http://127.0.0.1:$port/?tab=3&probe=1")")
  [[ $x == 'data-ex="none|ui-monospace|'* ]] && ok "example buttons ($theme theme): text-transform none, monospace ($x)" || bad "example buttons ($theme): $x"
done
# Unraid puts every tab of the page into ONE document and each tab page includes report.js: the Report tab, Settings and the
# image tab here, composed as DefaultPageLayout.php does (div.tabs > div.tab > div.content, the other tabs hidden). The image
# tab must start on its own (image.php is asked, Scan image is enabled), nothing may be started twice, and either tab may be
# absent. The same composition is used under Vulnerabilities (SHOW_TAB=yes) and under Settings, CVE Lens.
img_scenario image-compose "$PORT_IMG_COMPOSE" white
C=http://127.0.0.1:$PORT_IMG_COMPOSE; CW=$W/image-compose
mkdir -p "$CW/data/report"; cp "$W/demo-white/data/report/report.json" "$CW/data/report/report.json"
count() { grep -c "$1" "$CW/requests.log" 2>/dev/null || true; }
compose_check() {   # compose_check <label> <query> <report present 0|1> <image present 0|1>
  : >"$CW/requests.log"
  local raw dom_ n; raw=$(curl -s "$C/?compose=1&$2"); dom_=$(dom "$C/?compose=1&$2")
  n=$(grep -c '<script src="/plugins/unraid-cve-lens/assets/report.js' <<<"$raw")
  [ "$n" = $(( $3 + $4 )) ] && ok "composed page ($1): report.js included once per tab ($n)" || bad "composed page ($1): $n script tags"
  if [ "$4" = 1 ]; then
    grep -q 'id="uts-i-status">[^<]*Vulnerability database from 2026-11-05' <<<"$dom_" && ! grep -q 'id="uts-i-scan" disabled=""' <<<"$dom_" && grep -q '>Resolved as<' <<<"$dom_" \
      && [ "$(count '^image $')" = 1 ] && ok "composed page ($1): the image tab starts on its own: image.php asked once, Scan image enabled, result shown" \
      || bad "composed page ($1): image tab dead: $(grep -o 'id="uts-i-status">[^<]*' <<<"$dom_"); requests: $(tr '\n' ',' <"$CW/requests.log")"
  fi
  if [ "$3" = 1 ]; then
    grep -q 'class="uts-row' <<<"$dom_" && grep -qE 'id="uts-status">(Idle|Last scan)' <<<"$dom_" && [ "$(count '^status ')" = 1 ] && [ "$(count '^report ')" = 1 ] \
      && ok "composed page ($1): the Report tab is unchanged and polled once (no double start)" || bad "composed page ($1): report tab: $(grep -o 'id="uts-status">[^<]*' <<<"$dom_"); requests: $(tr '\n' ',' <"$CW/requests.log")"
  fi
  [ "$(grep -o 'id="uts-body"' <<<"$dom_" | wc -l)" -le 1 ] && [ "$(grep -o 'id="uts-fix"' <<<"$dom_" | wc -l)" -le 1 ] && [ "$(grep -o 'id="uts-i-fix"' <<<"$dom_" | wc -l)" -le 1 ] \
    && ok "composed page ($1): no duplicate ids between the tabs" || bad "composed page ($1): duplicate ids"
}
compose_check "Report shown, image tab hidden at load" "tab=1" 1 1
compose_check "image tab shown" "tab=3" 1 1
compose_check "Report tab absent" "tab=3&without=CveLensReport" 0 1
compose_check "image tab absent" "tab=1&without=CveLensImage" 1 0

# Unraid 6.12.15 layout
img_scenario image-612 "$PORT_IMG_612" white 6.12
DOM=$(dom "http://127.0.0.1:$PORT_IMG_612/?tab=3")
grep -q '>Resolved as<' <<<"$DOM" && grep -q 'What to enter' <<<"$DOM" && grep -q 'uts-cmd-pre' <<<"$DOM" && ok "image tab renders in the 6.12.15 webGui layout" || bad "image tab 6.12"
shot "http://127.0.0.1:$PORT_IMG_612/?tab=3" 1400,2300 "$W/page-612-3-light.png" && ok "screenshot page-612-3-light.png (tests/.work/render)" || bad "screenshot image 6.12"

# ---------------------------------------------------------------- empty state
E=$W/empty; mkdir -p "$E"; scenario empty "$PORT_EMPTY" black; wait_up "$PORT_EMPTY" || bad "empty harness"
DOM=$(dom "http://127.0.0.1:$PORT_EMPTY/?tab=1")
grep -q 'No report yet' <<<"$DOM" && ok "empty state shown without a report" || bad "empty state"
shot "http://127.0.0.1:$PORT_EMPTY/?tab=1" 1400,600 "$SHOTS/empty-dark.png" && ok "screenshot empty-dark.png" || bad "screenshot empty"
grep -qi 'fatal\|error\|warning:\|deprecated\|notice:' "$W"/*/php.log && { bad "PHP warnings in the harness logs:"; grep -hi 'fatal\|error\|warning:\|deprecated\|notice:' "$W"/*/php.log | head -5; } || ok "no PHP errors, warnings or notices while rendering"
exit $fail
