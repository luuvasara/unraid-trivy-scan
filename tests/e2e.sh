#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# e2e.sh - end-to-end against the local Docker with the pinned Trivy image and small, old public images.
# Pulls (if absent) nginx:1.19-alpine, alpine:3.10 and alpine:3.19.1 (tagged locally as alpine:3.19, so the
# registry check sees an outdated image); all test containers carry the label uts-e2e=1 and are the only ones
# scanned (UTS_PS_FILTER). A docker shim on PATH logs every docker command the plugin runs, to check the container
# roles. At the end it removes the test containers and every image or tag it added (images that were already on
# the host are left alone) and the data dir with the downloaded databases (E2E_KEEP=1 keeps them).
# Needs about 2 GB free disk (vulnerability DB 1.6 GB; the Java DB is not downloaded here).
# The Unraid OS scan runs against a local copy of an official Unraid release root filesystem (tests/unraid-os.sh:
# download, SHA-256 check and extraction under tests/.work/unraid-os, about 2.7 GB), never against this host's own
# directories and never against a server.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
S=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan
W=$HERE/tests/.work/e2e
TRIVY=$(bash "$S" image)
REAL_DOCKER=$(command -v docker)
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }

[ "$(df -Pk "$HERE" | awk 'NR==2{print $4}')" -gt 2200000 ] || { echo "FAIL less than 2.2 GB free disk"; exit 1; }
docker info >/dev/null 2>&1 || { echo "FAIL docker not reachable"; exit 1; }
rm -rf "${W:?}/run" "${W:?}/bin" "${W:?}"/*.log; mkdir -p "$W/appdata" "$W/run" "$W/bin" "$W/flash"
export UTS_DATA=$W/appdata/unraid-trivy-scan UTS_RUN=$W/run UTS_LOG=$W/scan.log UTS_CFG=$W/flash/cfg \
       UTS_CRON_FILE=$W/flash/cron UTS_PS_FILTER=label=uts-e2e=1 UTS_NOTIFY=$W/bin/notify UTS_UPDATE_CRON=/bin/true \
       UTS_PLUGIN_DIR=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan
OSROOT=$("$HERE/tests/unraid-os.sh" | tail -n1) && [ -f "$OSROOT/etc/unraid-version" ] || { echo "FAIL could not prepare the Unraid root filesystem"; exit 1; }
export UTS_OS_ROOT=$OSROOT UTS_OS_KERNEL; UTS_OS_KERNEL=$(cat "$HERE/tests/.work/unraid-os/kernel")
cat >"$W/bin/docker" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$W/docker.log"
exec "$REAL_DOCKER" "\$@"
EOF
printf '#!/bin/sh\nprintf "%%s|" "$@" >>%s/notify.log; echo >>%s/notify.log\n' "$W" "$W" >"$W/bin/notify"
chmod 755 "$W/bin/docker" "$W/bin/notify"
export PATH="$W/bin:$PATH"

# ---------------------------------------------------------------- test images and containers
ADDED=()   # image references this test added
have() { "$REAL_DOCKER" image inspect "$1" >/dev/null 2>&1; }
need() { have "$1" || { "$REAL_DOCKER" pull -q "$1" >/dev/null && ADDED+=("$1"); }; }
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  "$REAL_DOCKER" ps -aq --filter label=uts-e2e=1 | xargs -r "$REAL_DOCKER" rm -f >/dev/null
  "$REAL_DOCKER" rm -f uts-e2e-decoy >/dev/null 2>&1
  "$REAL_DOCKER" ps -aq --filter label=unraid-trivy-scan=1 | xargs -r "$REAL_DOCKER" rm -f >/dev/null
  local r; for r in "${ADDED[@]}"; do "$REAL_DOCKER" rmi "$r" >/dev/null 2>&1 && echo "cleanup: removed $r"; done
  [ "${E2E_KEEP:-0}" = 1 ] || rm -rf "$W/appdata"
}
trap cleanup EXIT
need "$TRIVY"; need nginx:1.19-alpine; need alpine:3.10
if have alpine:3.19; then echo "note: alpine:3.19 already on this host; the outdated-image check uses it as is"
else need alpine:3.19.1 && "$REAL_DOCKER" tag alpine:3.19.1 alpine:3.19 && ADDED=(alpine:3.19 "${ADDED[@]}"); fi
D="$REAL_DOCKER"
L=(--label uts-e2e=1 --network none)
"$D" rm -f uts-e2e-web uts-e2e-old uts-e2e-stopped uts-e2e-byid >/dev/null 2>&1
"$D" run -d "${L[@]}" --name uts-e2e-web nginx:1.19-alpine >/dev/null
"$D" run -d "${L[@]}" --name uts-e2e-old alpine:3.19 sleep 3600 >/dev/null
"$D" create "${L[@]}" --name uts-e2e-stopped alpine:3.10 sleep 3600 >/dev/null
ID310=$("$D" image inspect -f '{{.Id}}' alpine:3.10)
"$D" run -d "${L[@]}" --name uts-e2e-byid "$ID310" sleep 3600 >/dev/null
ok "test containers: web (nginx:1.19-alpine), old (alpine:3.19 = 3.19.1), byid (alpine:3.10 by ID), stopped (alpine:3.10)"

# report() evaluates PHP expressions written in this file against the report (test input only, never external data).
report() { php -r '$r=json_decode(file_get_contents($argv[1]),true); echo eval("return ".$argv[2].";"), "\n";' "$UTS_DATA/report/report.json" "$1"; }
cfg() { printf '%s\n' "$@" >"$UTS_CFG"; }
runs_with() { grep '^run ' "$W/docker.log" | grep -c -- "$1"; }

# ---------------------------------------------------------------- 1: running containers, no registry check
cfg 'SCOPE="running"' 'REGISTRY_CHECK="no"' 'JAVA_DB="no"' 'NOTIFY="yes"' 'TIMEOUT="30"' 'OS_SCAN="no"'
: >"$W/docker.log"
T0=$(date +%s); bash "$S" run; rc=$?
[ $rc -eq 0 ] && ok "scan 1 finished in $(( $(date +%s) - T0 )) s (includes the DB download)" || bad "scan 1 rc=$rc: $(tail -5 "$W/scan.log")"
[ -s "$UTS_DATA/cache/db/trivy.db" ] && ok "vulnerability DB downloaded into the data dir" || bad "no DB"
[ "$(report '$r["summary"]["images"]')" = 3 ] && [ "$(report '$r["summary"]["failed"]')" = 0 ] && ok "3 images scanned (running only), 0 failed" || bad "scan 1 counts: $(report 'json_encode($r["summary"])')"
[ "$(report '(int)($r["summary"]["by_severity"]["CRITICAL"]["total"] > 0 && $r["summary"]["total"] > 20)')" = 1 ] \
  && ok "findings: $(report '$r["summary"]["total"]') CVEs, $(report '$r["summary"]["by_severity"]["CRITICAL"]["total"]') critical" || bad "too few findings"
NAMES=$(report 'implode(",", array_map(fn($i)=>$i["name"], $r["images"]))')
grep -q 'nginx:1.19-alpine' <<<"$NAMES" && grep -q 'alpine:3.19' <<<"$NAMES" && grep -q "image ${ID310:7:12}" <<<"$NAMES" \
  && ok "image names: $NAMES" || bad "image names: $NAMES"
grep -q 'stopped' <<<"$(report 'json_encode($r["images"])')" && bad "stopped container scanned with scope=running" || ok "stopped container not scanned with scope=running"
[ "$(sed -n 's/^result=//p' "$UTS_DATA/report/last-run")" = ok ] && ok "last-run: ok" || bad "last-run: $(cat "$UTS_DATA/report/last-run")"
grep -q 'new fixable critical' "$W/notify.log" 2>/dev/null && ok "notification sent for new fixable critical CVEs" || bad "no notification: $(cat "$W/notify.log" 2>&1)"
# container roles, from the docker shim log
SOCK=$(grep '^run ' "$W/docker.log" | grep -c 'docker.sock')
[ "$SOCK" = 3 ] && ok "3 scanner containers got the Docker socket (one per image, by image ID)" || bad "socket runs: $SOCK"
[ "$(grep '^run ' "$W/docker.log" | grep 'docker.sock' | grep -vc -- '--network none')" = 0 ] && ok "every container with the socket ran with --network none" || bad "socket without --network none"
[ "$(grep '^run ' "$W/docker.log" | grep 'docker.sock' | grep -vc -- '/cache:ro')" = 0 ] && ok "the socket container mounts the DB read-only" || bad "socket container with writable DB"
[ "$(grep '^run ' "$W/docker.log" | grep 'download-db-only' | grep -c 'docker.sock')" = 0 ] && [ "$(runs_with download-db-only)" = 1 ] \
  && ok "DB download ran in its own container without the socket" || bad "DB container"
[ "$(grep '^run ' "$W/docker.log" | grep -c 'image-src docker.*sha256:[0-9a-f]\{64\}$')" = 3 ] && ok "local scans address images by full ID" || bad "scan not by ID"
[ "$(grep '^run ' "$W/docker.log" | grep -vc -- '--cap-drop ALL --security-opt no-new-privileges')" = 0 ] && ok "all Trivy containers: --cap-drop ALL, no-new-privileges, labelled" || bad "hardening flags"
[ -z "$("$D" ps -aq --filter label=unraid-trivy-scan=1)" ] && [ ! -e "$UTS_RUN/pid" ] && [ ! -e "$UTS_RUN/progress" ] && ok "no leftover containers, pid or progress file" || bad "leftovers after scan 1"
G1=$(report '$r["generated"]')
cp "$UTS_DATA/report/report.json" "$W/report-1.json"

# ---------------------------------------------------------------- 2: all containers, registry check with logins
printf '{"auths":{}}\n' >"$W/fake-docker-config.json"
export UTS_REG_AUTH=$W/fake-docker-config.json
cfg 'SCOPE="all"' 'REGISTRY_CHECK="yes"' 'REGISTRY_AUTH="yes"' 'JAVA_DB="no"' 'NOTIFY="yes"' 'OS_SCAN="yes"'
: >"$W/docker.log"; : >"$W/notify.log"
bash "$S" run || bad "scan 2 rc=$?: $(tail -5 "$W/scan.log")"
[ "$(report '$r["summary"]["images"]')" = 3 ] && grep -q 'uts-e2e-stopped' <<<"$(report 'json_encode($r["images"])')" \
  && ok "scope=all: stopped container listed (shares the alpine:3.10 image with byid)" || bad "scope=all: $(report 'json_encode(array_map(fn($i)=>[$i["name"],$i["containers"]], $r["images"]))')"
UPD=$(report 'implode(",", array_map(fn($i)=>$i["name"]."=".$i["update"], $r["images"]))')
grep -q 'nginx:1.19-alpine=current' <<<"$UPD" && grep -q 'alpine:3.19=newer' <<<"$UPD" && grep -q "image ${ID310:7:12}=skipped" <<<"$UPD" \
  && ok "registry states: $UPD" || bad "registry states: $UPD ($(report 'json_encode(array_map(fn($i)=>$i["update_note"], $r["images"]))'))"
GONE=$(report 'count(array_filter($r["cves"], fn($c)=>in_array($c["fix"], ["update","both"])))')
[ "${GONE:-0}" -gt 0 ] && ok "$GONE CVE(s) marked as fixed in the newer alpine:3.19 image" || bad "no CVE fixed by the newer image"
AUTH=$(grep '^run ' "$W/docker.log" | grep -c 'config.json')
[ "$AUTH" -ge 1 ] && [ "$(grep '^run ' "$W/docker.log" | grep 'config.json' | grep -c -e 'docker.sock' -e 'role=local' -e 'role=db')" = 0 ] \
  && ok "registry logins mounted only into registry containers ($AUTH), never with the socket" || bad "config.json placement"
[ "$(grep '^run ' "$W/docker.log" | grep 'role=remote' | grep -c 'docker.sock')" = 0 ] && ok "registry containers have no Docker socket" || bad "remote with socket"
# scan 2 adds the OS: notify exactly once, for the fixable criticals (not the NVD/CPE matches of OS packages, which never notify) that scan 1 did not have (none repeated)
NEWC=$(php -r '$f=fn($p)=>array_column(array_filter(json_decode(file_get_contents($p),true)["cves"], fn($c)=>$c["severity"]==="CRITICAL" && $c["fix"]!=="none" && count(array_filter($c["affected"], fn($a)=>($a["source"] ?? "")!=="cpe"))>0), "id");
  echo count(array_diff($f($argv[2]), $f($argv[1])));' "$W/report-1.json" "$UTS_DATA/report/report.json")
if [ "$NEWC" -gt 0 ]; then
  [ "$(grep -c . "$W/notify.log")" = 1 ] && grep -q "Trivy scan: $NEWC new fixable critical" "$W/notify.log" \
    && ok "one notification, for the $NEWC fixable critical CVE(s) new in this scan (OS added), none repeated from scan 1" || bad "notification: $(cat "$W/notify.log") (expected $NEWC)"
else [ ! -s "$W/notify.log" ] && ok "no second notification for the same fixable criticals" || bad "repeated notification: $(cat "$W/notify.log")"; fi
# the Unraid OS target (same run): real findings from the release's root filesystem, container role from the shim log
OSL=$(grep '^run ' "$W/docker.log" | grep -- 'role=os')
[ "$(grep -c . <<<"$OSL")" = 1 ] && grep -q -- '--network none' <<<"$OSL" && ! grep -q -e 'docker.sock' -e 'config.json' <<<"$OSL" \
  && ok "OS scan: one container, --network none, no Docker socket, no registry logins" || bad "OS container: $OSL"
TG=$(grep -o 'target=/rootfs/[a-z0-9]*,readonly,bind-recursive=disabled' <<<"$OSL" | sed 's/^target=\/rootfs\///; s/,.*//' | sort | tr '\n' ' ')
[ "$TG" = "bin lib lib64 sbin usr " ] && [ "$(grep -o -- '--mount' <<<"$OSL" | wc -l)" = 5 ] \
  && ok "OS scan mounts: /usr /lib /lib64 /bin /sbin of the release, read-only, non-recursive" || bad "OS mounts: '$TG'"
OSN=$(report 'implode(" ", array_map(fn($i)=>$i["kind"].":".$i["scan"], $r["images"]))')
OSI=$(report 'array_search("os", array_column($r["images"], "kind"))')
[ "$(report '$r["images"]['"$OSI"']["name"]." ".$r["images"]['"$OSI"']["scan"]')" = "Unraid OS $(sed -n 's/^version="\(.*\)"$/\1/p' "$OSROOT/etc/unraid-version") ok" ] \
  && [ "$(report '$r["summary"]["images"]')" = 3 ] && ok "report: Unraid OS target scanned next to the 3 images ($OSN)" || bad "OS target: $OSN"
OSV=$(report '$r["images"]['"$OSI"']["vulns"]')
[ "${OSV:-0}" -gt 0 ] && ok "OS findings: $OSV ($(report 'implode(", ", array_map(fn($s)=>$s."=".count(array_filter($r["cves"], fn($c)=>$c["severity"]===$s && in_array('"$OSI"', array_column($c["affected"],"img")))), ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]))') distinct CVEs)" || bad "no OS findings"
report 'implode("\n", array_unique(array_map(fn($a)=>$a["path"] ?: $a["target"], array_merge(...array_map(fn($c)=>array_filter($c["affected"], fn($a)=>$a["img"]==='"$OSI"'), $r["cves"])))))' >"$W/os-paths.txt"
grep -q '^usr/local/unraid-api/node_modules/' "$W/os-paths.txt" && grep -q '^usr/bin/' "$W/os-paths.txt" \
  && ok "OS findings carry file paths: $(grep -c . "$W/os-paths.txt") distinct, e.g. $(grep -m1 '^usr/bin/' "$W/os-paths.txt"), $(grep -m1 '^usr/local/unraid-api/' "$W/os-paths.txt")" || bad "OS paths: $(head -3 "$W/os-paths.txt")"
NPK=$(find "$OSROOT/var/lib/pkgtools/packages" -maxdepth 1 -type f | wc -l)
[ "$(report '$r["host"]["package_count"]')" = "$NPK" ] && [ "$(report '$r["host"]["kernel"]')" = "$UTS_OS_KERNEL" ] \
  && ok "OS inventory: $NPK Slackware packages, kernel $UTS_OS_KERNEL" || bad "OS inventory: $(report '$r["host"]["package_count"]." ".$r["host"]["kernel"]')"
# the OS package match (Grype against NVD/CPE; defaults OS_PKG_MATCH=yes, OS_PKG_DB_KEEP=yes)
PM=$(report '$r["host"]["pkg_match"]." ".$r["host"]["base"]." ".$r["host"]["mapped_count"]')
read -r PMR PMB PMC <<<"$PM"
[ "$PMR" = ok ] && [ "$PMB" = slackware ] && [ "${PMC:-0}" -gt 50 ] && ok "OS package match: pkg_match=ok, base=slackware, $PMC packages mapped to a CPE" || bad "OS package match: '$PM' ($(report '$r["host"]["pkg_error"]'))"
CPEN=$(report 'count(array_filter($r["cves"], fn($c)=>count(array_filter($c["affected"], fn($a)=>$a["img"]==='"$OSI"' && ($a["source"] ?? "")==="cpe"))>0))')
CPES=$(report 'implode(", ", array_map(fn($s)=>$s."=".count(array_filter($r["cves"], fn($c)=>$c["severity"]===$s && count(array_filter($c["affected"], fn($a)=>$a["img"]==='"$OSI"' && ($a["source"] ?? "")==="cpe"))>0)), ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]))')
[ "${CPEN:-0}" -gt 0 ] && ok "OS package match: $CPEN distinct CVE(s) from CPE matching on the OS target ($CPES)" || bad "no CPE findings on the OS target"
PKL=$(grep '^run ' "$W/docker.log" | grep 'role=pkgmatch')
[ "$(grep -c . <<<"$PKL")" = 1 ] && grep -q -- '--network none' <<<"$PKL" && ! grep -q -e 'docker.sock' -e 'config.json' <<<"$PKL" \
  && ok "Grype match container: one, --network none, no Docker socket, no registry logins" || bad "Grype match container: $PKL"
OVM=$(report 'implode(" ", array_map(fn($c)=>$c["id"], array_filter($r["cves"], fn($c)=>preg_match("/^CVE-(\\d{4})-/", $c["id"], $m) && $m[1] < 2024 && count(array_filter($c["affected"], fn($a)=>$a["img"]==='"$OSI"' && ($a["source"] ?? "")==="cpe" && stripos(($a["pkg"] ?? $a["package"] ?? ""), "ovmf")!==false))>0)))')
# Before the version was normalised, stable202602 was unparseable and matched 29 old CVEs. The old tianocore:edk2
# entries that still match are NVD records without a version range ("none (unknown)"): those are listed as not
# counted (host.suppressed), so no pre-2024 ovmf CVE may be a finding.
NOVM=$(wc -w <<<"$OVM")
NSUP=$(report 'count(array_filter($r["host"]["suppressed"], fn($x)=>$x[1]==="ovmf" && strpos($x[2], "no version range")!==false))')
[ "$NOVM" = 0 ] && [ "$NSUP" -gt 0 ] && ok "ovmf: no pre-2024 CPE finding; $NSUP range-less NVD entries listed as not counted" || bad "ovmf: $NOVM old finding(s): $OVM; suppressed $NSUP"
[ "$(grep '^run ' "$W/docker.log" | grep -c -- '-grypedb ')" = 1 ] && ok "Grype DB downloaded once in scan 2 (kept for the later scans)" || bad "Grype DB downloads in scan 2: $(grep '^run ' "$W/docker.log" | grep -c -- '-grypedb ')"
grep -q 'and the Unraid OS scanned, 0 failed' "$UTS_DATA/report/last-run" && ok "last-run: $(sed -n 's/^message=//p' "$UTS_DATA/report/last-run")" || bad "last-run: $(cat "$UTS_DATA/report/last-run")"
cfg 'SCOPE="all"' 'REGISTRY_CHECK="yes"' 'REGISTRY_AUTH="no"' 'JAVA_DB="no"' 'OS_SCAN="no"'; : >"$W/docker.log"; unset UTS_REG_AUTH
cp "$UTS_DATA/report/report.json" "$W/report-registry.json"   # kept for the README screenshots

# ---------------------------------------------------------------- 3: per-image timeout -> failures with reason
cfg 'SCOPE="running"' 'REGISTRY_CHECK="no"' 'JAVA_DB="no"' 'NOTIFY="no"' 'OS_SCAN="no"'
UTS_TRIVY_TIMEOUT=1ms bash "$S" run || bad "scan 3 rc=$?"
F=$(report '$r["summary"]["failed"]')
REASON=$(report '$r["images"][0]["error"]')
[ "$F" = 3 ] && [[ $REASON == "timed out after"* ]] && ok "simulated timeout: 3 images listed as failed, reason '$REASON'" || bad "timeout: failed=$F reason=$REASON"
[ "$(sed -n 's/^message=//p' "$UTS_DATA/report/last-run")" = "3 image(s) scanned, 3 failed" ] && ok "last-run message counts the failures" || bad "last-run: $(cat "$UTS_DATA/report/last-run")"
cfg 'SCOPE="running"' 'REGISTRY_CHECK="no"' 'JAVA_DB="no"' 'NOTIFY="no"' 'OS_SCAN="yes"'
UTS_PS_FILTER=label=uts-e2e-none=1 UTS_TRIVY_TIMEOUT=1ms bash "$S" run || bad "scan 3b rc=$?"
REASON=$(report '$r["images"][0]["kind"]." ".$r["images"][0]["scan"].": ".$r["images"][0]["error"]')
[[ $REASON == "os failed: timed out after"* ]] && [ "$(report '$r["summary"]["failed"]')" = 1 ] && ok "simulated OS-scan timeout: listed as failed, '$REASON'" || bad "OS timeout: $REASON"

# ---------------------------------------------------------------- 4: stop (label-scoped), lock, previous report kept
cfg 'SCOPE="all"' 'REGISTRY_CHECK="yes"' 'JAVA_DB="no"' 'NOTIFY="no"' 'OS_SCAN="no"'
"$D" run -d --name uts-e2e-decoy --entrypoint sleep "$TRIVY" 600 >/dev/null
G3=$(report '$r["generated"]')
bash "$S" start >/dev/null
for _ in $(seq 1 100); do [ -n "$("$D" ps -q --filter label=unraid-trivy-scan=1)" ] && break; sleep 0.2; done
[ -n "$("$D" ps -q --filter label=unraid-trivy-scan=1)" ] && ok "background scan started a labelled Trivy container" || bad "no running scan container seen"
OUT=$(bash "$S" run 2>&1); rc=$?
[ $rc -eq 3 ] && grep -q 'already running' <<<"$OUT" && ok "second scan refused while one runs (lock)" || bad "lock: rc=$rc $OUT"
grep -q '^running=yes' <<<"$(bash "$S" status)" && ok "status: running=yes" || bad "status while running"
T0=$(date +%s); bash "$S" stop >/dev/null
[ $(( $(date +%s) - T0 )) -le 15 ] && ok "stop returned in $(( $(date +%s) - T0 )) s" || bad "stop slow"
[ -z "$("$D" ps -aq --filter label=unraid-trivy-scan=1)" ] && ok "stop removed all containers labelled unraid-trivy-scan=1" || bad "labelled containers left after stop"
[ -n "$("$D" ps -q --filter name=^uts-e2e-decoy$)" ] && ok "unlabelled container from the same Trivy image survived stop" || bad "decoy was killed"
grep -q '^running=no' <<<"$(bash "$S" status)" && [ ! -e "$UTS_RUN/pid" ] && ok "status: running=no, pid file gone" || bad "status after stop"
[ "$(sed -n 's/^result=//p' "$UTS_DATA/report/last-run")" = stopped ] && [ "$(report '$r["generated"]')" = "$G3" ] \
  && ok "last-run=stopped, previous report kept" || bad "after stop: $(cat "$UTS_DATA/report/last-run")"
flock -n "$UTS_RUN/lock" true && ok "lock released after stop" || bad "lock still held"
"$D" rm -f uts-e2e-decoy >/dev/null

# ---------------------------------------------------------------- 5: update-db only, DB reused
: >"$W/docker.log"; cfg 'JAVA_DB="no"'
bash "$S" update-db --foreground && ok "update-db: ok" || bad "update-db"
[ "$(runs_with 'download-db-only')" = 1 ] && [ "$(runs_with 'image-src')" = 0 ] && ok "update-db ran only the DB container, no scan" || bad "update-db containers"
[ "$G1" -le "$(report '$r["generated"]')" ] && ok "report still readable after all runs" || bad "report"

# ---------------------------------------------------------------- 6: a locally built image is not sent to the registry check
# A compose/docker-build image has no RepoDigests; asking Docker Hub for library/<name> only gave "authentication required".
printf 'FROM alpine:3.10\n' | "$D" build -q -t uts-e2e-local:1 - >/dev/null && ADDED+=(uts-e2e-local:1)
"$D" run -d "${L[@]}" --name uts-e2e-local uts-e2e-local:1 sleep 3600 >/dev/null
cfg 'SCOPE="running"' 'REGISTRY_CHECK="yes"' 'JAVA_DB="no"' 'NOTIFY="no"' 'OS_SCAN="no"'; : >"$W/docker.log"
bash "$S" run || bad "scan 6 rc=$?"
BRD=$("$D" image inspect -f '{{json .RepoDigests}}' uts-e2e-local:1)
if [ "$BRD" != "[]" ] && [ "$BRD" != null ]; then
  echo "skip locally built image: RepoDigests=$BRD (containerd image store: built images get a digest; Unraid uses overlay2)"
else
LOC=$(report 'implode("|", array_map(fn($i)=>$i["update"].":".$i["update_note"], array_filter($r["images"], fn($i)=>$i["name"]==="uts-e2e-local:1")))')
[ "$LOC" = "skipped:image was built locally (no registry digest)" ] && ! grep '^run ' "$W/docker.log" | grep 'role=remote' | grep -q 'uts-e2e-local' \
  && ok "locally built image: registry check skipped with the reason, no registry container for it" || bad "local image: '$LOC'"
fi
grep -q 'nginx:1.19-alpine=current' <<<"$(report 'implode(",", array_map(fn($i)=>$i["name"]."=".$i["update"], $r["images"]))')" \
  && ok "pulled images are still registry-checked next to it" || bad "registry check of pulled images: $(report 'json_encode(array_column($r["images"], "update", "name"))')"
"$D" rm -f uts-e2e-local >/dev/null
exit $fail
