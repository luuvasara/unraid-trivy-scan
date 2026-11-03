#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# unit.sh - offline unit tests. A fake `docker` on PATH records calls, so no real container or image is touched.
# Covers: cron validation (bash and PHP agree on every case), the settings reader (bash and PHP) against hostile
# files, include/validate.php in update.php's scope, `apply` (cron only for a valid schedule), `uninstall` guards,
# the .plg lifecycle rules, and include/aggregate.php on fixture Trivy JSON (tests/aggregate-test.php).
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan
S=$P/scripts/trivy-scan
W=$HERE/tests/.work/unit; rm -rf "$W"; mkdir -p "$W/bin"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }

cat >"$W/bin/docker" <<EOF
#!/bin/sh
echo "docker \$*" >>"$W/docker.log"
case "\$1" in ps) exit 0 ;; info) exit 0 ;; esac
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_JSON:-}" ] && [ -z "\${FAKE_OS_FAIL:-}" ] && { cat "\$FAKE_OS_JSON"; exit 0; } ;; esac   # a large Trivy result
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_FAIL:-}" ] && { echo "FATAL fake failure" >&2; exit 1; }; echo '{"SchemaVersion":2,"Results":[]}' ;; esac
exit 0
EOF
chmod 755 "$W/bin/docker"
export PATH="$W/bin:$PATH"
cd "$W" || exit 1                       # globbing check: a "*" must never expand to file names here
touch "$W/aaa-glob-trap" "$W/zzz-glob-trap"

# ---------------------------------------------------------------- cron: bash and PHP must agree
php_valid() { php -r 'require $argv[1]; echo uts_valid($argv[2], $argv[3]) ? "1" : "0";' "$P/include/lib.php" "$1" "$2"; }
sh_valid()  { printf 'SCHEDULE="%s"\n' "$1" >"$W/c.cfg"; UTS_CFG=$W/c.cfg bash "$S" config | grep -q '^INVALID=' && echo 0 || echo 1; }
while IFS='|' read -r want expr; do
  [ -z "$expr$want" ] && continue
  a=$(sh_valid "$expr"); b=$(php_valid SCHEDULE "$expr")
  if [ "$a" = "$want" ] && [ "$b" = "$want" ]; then ok "cron '$expr' -> $want (bash and PHP)"; else bad "cron '$expr': want $want, bash $a, php $b"; fi
done <<'EOF'
1|
1|30 3 * * *
1|*/15 * * * *
1|0 0-23/2 1,15 1-12 0-7
1|59 23 31 12 7
1|00 03 * * 0
0|* * * *
0|* * * * * *
0|60 * * * *
0|* 24 * * *
0|* * 0 * *
0|* * * 13 *
0|* * * * 8
0|5-1 * * * *
0|*/0 * * * *
0|1,,2 * * * *
0|1, * * * *
0|@daily
0|30 3 * * mon
0|30  3 * * *
0|$(touch PWN) * * * *
0|* * * * *; touch PWN
0|`id` * * * *
EOF
[ ! -e "$W/PWN" ] && ok "no command substitution ran while reading schedules" || bad "a schedule executed a command"

# ---------------------------------------------------------------- settings reader against a hostile file
printf '%s\r\n' 'SCHEDULE="$(touch PWN2)"' 'SCOPE=all; touch PWN3' 'TIMEOUT="060"' 'NOTIFY="no"' 'PATH="/evil"' \
  'REGISTRY_CHECK=yes' 'JAVA_DB="maybe"' 'DASH_TILE="no" ' 'garbage line' '=x' 'SHOW_TAB="yes"' >"$W/h.cfg"
printf '%s\n' '* * * * * touch /PWN4' >>"$W/h.cfg"
OUT=$(UTS_CFG=$W/h.cfg bash "$S" config)
want='DASH_TILE=yes
JAVA_DB=yes
NOTIFY=no
OS_SCAN=yes
REGISTRY_AUTH=no
REGISTRY_CHECK=yes
REMOVE_DATA=no
SCHEDULE=
SCOPE=running
SHOW_TAB=yes
TIMEOUT=60'
[ "$(grep -v '^INVALID=' <<<"$OUT")" = "$want" ] && ok "bash reader: valid keys taken, invalid -> defaults, unknown keys ignored, CRLF ok" \
  || bad "bash reader output: $(tr '\n' ' ' <<<"$OUT")"
inv_sh=$(sed -n 's/^INVALID=//p' <<<"$OUT" | tr ' ' '\n' | sort | tr '\n' ' ')
PHPOUT=$(php -r 'require $argv[1]; $c = uts_config($p, $argv[2]); ksort($c); foreach ($c as $k=>$v) echo "$k=$v\n"; $k = array_keys($p); sort($k); echo "INVALID=", implode(" ", $k), "\n";' "$P/include/lib.php" "$W/h.cfg")
[ "$(grep -v '^INVALID=' <<<"$PHPOUT")" = "$want" ] && ok "PHP reader gives the same settings" || bad "PHP reader: $(tr '\n' ' ' <<<"$PHPOUT")"
inv_php=$(sed -n 's/^INVALID=//p' <<<"$PHPOUT" | tr ' ' '\n' | sort | tr '\n' ' ')
[ "$inv_sh" = "$inv_php" ] && [ -n "$inv_sh" ] && ok "bash and PHP flag the same invalid keys: $inv_sh" || bad "invalid keys differ: bash '$inv_sh' php '$inv_php'"
[ ! -e "$W/PWN2" ] && [ ! -e "$W/PWN3" ] && [ ! -e /PWN4 ] && ok "hostile settings file executed nothing" || bad "hostile settings executed a command"
DEF_SH=$(sed -n 's/^declare -A DEF=(\(.*\)/\1/p;/^ *\[NOTIFY\]/p' "$S" | tr -d '()' | tr ' ' '\n' | grep '^\[' | sed 's/^\[\([A-Z_]*\)\]=/\1=/; s/"//g' | sort)
DEF_PHP=$(php -r 'require $argv[1]; $d = UTS_DEFAULTS; ksort($d); foreach ($d as $k=>$v) echo "$k=$v\n";' "$P/include/lib.php")
[ "$DEF_SH" = "$DEF_PHP" ] && ok "defaults identical in scripts/trivy-scan and include/lib.php" || bad "defaults differ: $(tr '\n' ' ' <<<"$DEF_SH") vs $(tr '\n' ' ' <<<"$DEF_PHP")"
[ "$(UTS_CFG=$W/none.cfg bash "$S" config)" = "$DEF_PHP" ] && [ "$(UTS_CFG=$W/none.cfg php -r 'require $argv[1]; $c=uts_config(); ksort($c); foreach ($c as $k=>$v) echo "$k=$v\n";' "$P/include/lib.php")" = "$DEF_PHP" ] \
  && ok "missing settings file -> defaults" || bad "missing settings file"

# ---------------------------------------------------------------- validate.php in update.php's scope
# vphp evaluates PHP array literals written in this file (test input only, never external data).
vphp() {   # vphp '<php array literal for $_POST>' '<php array literal for $keys>' -> save=<0|1> post=<json> keys=<json>
  php -r '$docroot="/nonexistent"; $_POST = eval("return ".$argv[2].";"); $keys = eval("return ".$argv[3].";"); $save = true;
          ob_start(); include $argv[1]; $msg = ob_get_clean();
          echo "save=", (int)$save, " post=", json_encode($_POST), " keys=", json_encode($keys), " msg=", trim($msg), "\n";' \
    "$P/include/validate.php" "$1" "$2"
}
R=$(vphp "['#file'=>'/x','SCHEDULE'=>' 30  3 * * 0 ','SCOPE'=>'all','TIMEOUT'=>'060','csrf_token'=>'t','EVIL'=>'1']" "['NOTIFY'=>'no','OLD'=>'x','SCOPE'=>'bad']")
grep -q 'save=1' <<<"$R" && grep -q '"SCHEDULE":"30 3 \* \* 0"' <<<"$R" && grep -q '"TIMEOUT":"60"' <<<"$R" \
  && ! grep -q 'csrf_token\|EVIL' <<<"$R" && grep -q 'keys={"NOTIFY":"no"}' <<<"$R" \
  && ok "validate.php: normalises, drops unknown keys and csrf_token, cleans the merged file keys" || bad "validate.php valid case: $R"
R=$(vphp "['SCHEDULE'=>'\$(reboot) * * * *','SCOPE'=>'all']" "[]")
grep -q 'save=0' <<<"$R" && grep -q 'NOT saved.*SCHEDULE' <<<"$R" && ok "validate.php: invalid schedule refuses the save" || bad "validate.php invalid: $R"
R=$(vphp "['SCHEDULE'=>\"30 3 * * *\n* * * * * touch /x\"]" "[]")
grep -q 'save=0' <<<"$R" && ok "validate.php: newline injection refused" || bad "validate.php newline: $R"
R=$(vphp "['SCOPE'=>['all'],'NOTIFY'=>'yes']" "[]")
grep -q 'save=0' <<<"$R" && ok "validate.php: array value refused" || bad "validate.php array: $R"
R=$(vphp "['SHOW_TAB'=>'yes\"','TIMEOUT'=>'4']" "[]")
grep -q 'save=0' <<<"$R" && grep -q 'SHOW_TAB, TIMEOUT' <<<"$R" && ok "validate.php: quote in value and out-of-range timeout refused" || bad "validate.php misc: $R"

# ---------------------------------------------------------------- apply: cron only for a valid schedule
export UTS_CRON_FILE=$W/cron/uts.cron UTS_UPDATE_CRON=$W/bin/update_cron
printf '#!/bin/sh\necho x >>%s/update_cron.log\n' "$W" >"$W/bin/update_cron"; chmod 755 "$W/bin/update_cron"
printf 'SCHEDULE="15 4 * * 1"\n' >"$W/a.cfg"
UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ "$(grep -v '^#' "$UTS_CRON_FILE")" = "15 4 * * 1 /usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan cron >/dev/null 2>&1" ] \
  && [ -s "$W/update_cron.log" ] && ok "apply: valid schedule -> cron file + update_cron" || bad "apply valid: $(cat "$UTS_CRON_FILE" 2>&1)"
printf 'SCHEDULE="15 4 * * 1\n* * * * * touch %s/PWN5"\n' "$W" >"$W/a.cfg"
UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: invalid (multi-line) schedule -> no cron file" || bad "apply invalid wrote: $(cat "$UTS_CRON_FILE")"
printf 'SCHEDULE=""\n' >"$W/a.cfg"; UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: empty schedule -> no cron file" || bad "apply empty"
grep -q 'docker run\|docker pull' "$W/docker.log" 2>/dev/null && bad "apply/config touched docker run/pull" || ok "apply and config never run or pull an image"

# ---------------------------------------------------------------- uninstall guards
: >"$W/docker.log"
mkdir -p "$W/d1/unraid-trivy-scan/cache" "$W/run"
printf 'REMOVE_DATA="yes"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d1/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ ! -e "$W/d1/unraid-trivy-scan" ] && grep -q '^docker rmi aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c$' "$W/docker.log" \
  && ok "uninstall REMOVE_DATA=yes: data dir removed, docker rmi of the pinned reference only" || bad "uninstall yes: $(cat "$W/docker.log")"
mkdir -p "$W/d2/other"; UTS_CFG=$W/u.cfg UTS_DATA=$W/d2/other UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d2/other" ] && ok "uninstall: refuses a data path not ending in /unraid-trivy-scan" || bad "uninstall removed an unexpected path"
mkdir -p "$W/victim"; touch "$W/victim/keep"; mkdir -p "$W/d3"; ln -s "$W/victim" "$W/d3/unraid-trivy-scan"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d3/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -e "$W/victim/keep" ] && ok "uninstall: a symlinked data dir is not followed" || bad "uninstall followed a symlink"
mkdir -p "$W/d4/unraid-trivy-scan"; : >"$W/docker.log"; printf 'REMOVE_DATA="no"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d4/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d4/unraid-trivy-scan" ] && ! grep -q rmi "$W/docker.log" && ok "uninstall REMOVE_DATA=no keeps data and image" || bad "uninstall no"
grep -q 'docker rm -f\|docker ps -aq --filter label=unraid-trivy-scan=1' "$W/docker.log" && ok "uninstall stops only containers labelled unraid-trivy-scan=1" || bad "uninstall label filter: $(cat "$W/docker.log")"

# ---------------------------------------------------------------- OS scan: what the OS container gets
# A fake Unraid root with the system dirs, the dirs that must never be mounted, a symlinked /opt pointing at /mnt and
# a hostile unraid-version. `run` goes through the real script and the real aggregator; only docker is fake.
OR=$W/osroot
mkdir -p "$OR"/usr/bin "$OR"/lib/modules "$OR"/lib64 "$OR"/bin "$OR"/sbin "$OR"/mnt/user "$OR"/boot "$OR"/proc "$OR"/sys \
         "$OR"/etc "$OR"/var/lib/docker "$OR"/var/lib/pkgtools/packages "$W/osdata/unraid-trivy-scan/cache/db" "$W/osrun"
ln -sfn "$OR/mnt" "$OR/opt"
touch "$OR/var/lib/pkgtools/packages/bash-5.3.003-x86_64-1" "$OR/var/lib/pkgtools/packages/docker-29.8.2-x86_64-1_LT"
echo x >"$W/osdata/unraid-trivy-scan/cache/db/trivy.db"
osrun() {   # osrun <cfg lines...>: one offline `run` with the fake docker and the fake root
  printf '%s\n' "$@" >"$W/os.cfg"; : >"$W/docker.log"
  UTS_CFG=$W/os.cfg UTS_DATA=$W/osdata/unraid-trivy-scan UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_OS_ROOT=$OR \
    UTS_OS_KERNEL=6.18.58-Unraid UTS_PLUGIN_DIR=$P UTS_NOTIFY=$W/none UTS_CRON_FILE=$W/os.cron bash "$S" run
}
printf 'version="7.3.4"\n' >"$OR/etc/unraid-version"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' && ok "run with OS_SCAN=yes (fake docker) exits 0" || bad "OS run rc=$?: $(tail -3 "$W/os.log")"
OSL=$(grep -- '--label unraid-trivy-scan.role=os' "$W/docker.log")
[ "$(grep -c . <<<"$OSL")" = 1 ] && ok "one OS scanner container" || bad "OS containers: $OSL"
grep -q -- '--cap-drop ALL --security-opt no-new-privileges --network none' <<<"$OSL" && ok "OS container: --cap-drop ALL, no-new-privileges, --network none" || bad "OS hardening: $OSL"
grep -q 'docker.sock' <<<"$OSL" && bad "OS container got the Docker socket" || ok "OS container has no Docker socket"
TG=$(grep -o 'target=/rootfs/[a-z0-9]*,readonly,bind-recursive=disabled' <<<"$OSL" | sed 's/^target=\/rootfs\///; s/,.*//' | sort | tr '\n' ' ')
[ "$TG" = "bin lib lib64 sbin usr " ] && ok "OS mounts: exactly /usr /lib /lib64 /bin /sbin, read-only, non-recursive (symlinked /opt skipped)" || bad "OS mounts: '$TG'"
[ "$(grep -o -- '--mount' <<<"$OSL" | wc -l)" = 5 ] && [ "$(grep -o -- ' -v ' <<<"$OSL" | wc -l)" = 1 ] && grep -q -- "-v $W/osdata/unraid-trivy-scan/cache:/cache:ro" <<<"$OSL" \
  && ok "OS container: 5 mounts plus the DB read-only, nothing else" || bad "OS extra mounts: $OSL"
grep -qE "source=$OR/(mnt|boot|proc|sys|etc|var|dev|root|opt)|source=/(mnt|boot|proc|sys|etc|var)" <<<"$OSL" && bad "a forbidden directory was mounted" \
  || ok "never mounted: /mnt /boot /proc /sys /etc /var (incl. /var/lib/docker) /opt-symlink"
grep -q -- 'rootfs --cache-dir /cache .*--offline-scan --scanners vuln .*--skip-dirs /rootfs/lib/modules .* /rootfs$' <<<"$OSL" \
  && ok "OS scan: trivy rootfs /rootfs, offline, vuln only, /lib/modules skipped" || bad "OS trivy args: $OSL"
osrep() { php -r '$r=json_decode(file_get_contents($argv[1]),true); echo eval("return ".$argv[2].";"), "\n";' "$W/osdata/unraid-trivy-scan/report/report.json" "$1"; }
[ "$(osrep '$r["images"][0]["kind"]." ".$r["images"][0]["name"]." ".$r["summary"]["os"]')" = "os Unraid OS 7.3.4 ok" ] && ok "report: OS target 'Unraid OS 7.3.4', scanned" || bad "report OS: $(osrep 'json_encode($r["images"])')"
[ "$(osrep 'json_encode([$r["host"]["kernel"], $r["host"]["packages"]])')" = '["6.18.58-Unraid",[["bash","5.3.003","1"],["docker","29.8.2","1_LT"]]]' ] \
  && ok "report: kernel and the Slackware package list read on the host" || bad "report host: $(osrep 'json_encode($r["host"])')"
[ "$(sed -n 's/^message=//p' "$W/osdata/unraid-trivy-scan/report/last-run")" = "0 image(s) and the Unraid OS scanned, 0 failed" ] && ok "last-run message names the OS" || bad "last-run: $(cat "$W/osdata/unraid-trivy-scan/report/last-run")"
printf 'version="$(touch %s/PWN6)"\n' "$W" >"$OR/etc/unraid-version"
FAKE_OS_FAIL=1 osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ ! -e "$W/PWN6" ] && [ "$(osrep '$r["images"][0]["name"]')" = "Unraid OS unknown" ] && ok "hostile unraid-version: not executed, shown as 'unknown'" || bad "hostile unraid-version"
[ "$(osrep '$r["images"][0]["scan"]." ".$r["images"][0]["error"]')" = "failed FATAL fake failure" ] && [ "$(sed -n 's/^message=//p' "$W/osdata/unraid-trivy-scan/report/last-run")" = "0 image(s) and the Unraid OS scanned, 1 failed" ] \
  && ok "failed OS scan: listed with Trivy's error line, counted as failed" || bad "OS failure: $(osrep 'json_encode($r["images"])')"
osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
grep -q 'role=os' "$W/docker.log" && bad "OS_SCAN=no still ran an OS container" || ok "OS_SCAN=no: no OS container"
[ "$(osrep 'json_encode($r["host"])." ".$r["summary"]["os"]')" = "null off" ] && ok "OS_SCAN=no: no OS target in the report" || bad "OS_SCAN=no report"

# ---------------------------------------------------------------- data dir follows Docker's appdata location (F2)
# Real file: /boot/config/docker.cfg line 4 on a 7.3.4 server is DOCKER_APP_CONFIG_PATH="/mnt/user/appdata/" (quoted, trailing slash).
dd_sh()  { printf '%s' "$1" >"$W/dd.cfg"; UTS_DOCKER_CFG=$W/dd.cfg bash "$S" datadir; }
dd_php() { printf '%s' "$1" >"$W/dd.cfg"; UTS_DOCKER_CFG=$W/dd.cfg php -r 'require $argv[1]; echo uts_path("data");' "$P/include/lib.php"; }
while IFS='|' read -r want cfg; do
  [ -z "$want" ] && continue
  cfg=${cfg//\\n/$'\n'}
  a=$(dd_sh "$cfg"); b=$(dd_php "$cfg")
  [ "$a" = "$want" ] && [ "$b" = "$want" ] && ok "datadir '${cfg//$'\n'/ ; }' -> $want (bash and PHP)" || bad "datadir '$cfg': want $want, bash '$a', php '$b'"
done <<'CASES'
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user/appdata/"\nDOCKER_APP_UNRAID_PATH=""\n
/mnt/cache/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/cache/appdata/"\n
/mnt/fast_pool/docker-appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH=/mnt/fast_pool/docker-appdata\n
/mnt/cache/b/unraid-trivy-scan|A=1\nDOCKER_APP_CONFIG_PATH="/mnt/user/a"\nDOCKER_APP_CONFIG_PATH="/mnt/cache/b/"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_ENABLED="yes"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH=""\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/etc/appdata"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user/../../etc"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user/a b"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user/a:/b"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user/$(id)"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/"\n
/mnt/user/appdata/unraid-trivy-scan|DOCKER_APP_CONFIG_PATH="/mnt/user//x"\n
CASES
[ "$(UTS_DOCKER_CFG=$W/nonexistent.cfg bash "$S" datadir)" = /mnt/user/appdata/unraid-trivy-scan ] && ok "datadir: no docker.cfg -> /mnt/user/appdata/unraid-trivy-scan" || bad "datadir without docker.cfg"
# array stopped / location missing: nothing is created, not even last-run (mkdir -p would build /mnt/... in RAM)
printf '#!/bin/sh\nexit 1\n' >"$W/bin/docker-down"; MISSING=$W/not-mounted/appdata
PATH="$W/bin:$PATH" UTS_DATA=$MISSING/unraid-trivy-scan UTS_RUN=$W/run-miss UTS_LOG=$W/miss.log UTS_CFG=$W/none.cfg bash "$S" run
RC=$?
[ "$RC" = 1 ] && [ ! -e "$W/not-mounted" ] && grep -q 'does not exist' "$W/miss.log" && ok "missing appdata parent: scan refuses (rc 1), logs why, creates nothing" || bad "missing parent: rc=$RC, $(ls "$W/not-mounted" 2>&1), $(cat "$W/miss.log" 2>&1)"
FDOCK=$W/bin2; mkdir -p "$FDOCK"; printf '#!/bin/sh\nexit 1\n' >"$FDOCK/docker"; chmod 755 "$FDOCK/docker"
PATH="$FDOCK:$PATH" UTS_DATA=$MISSING/unraid-trivy-scan UTS_RUN=$W/run-miss UTS_LOG=$W/miss.log UTS_CFG=$W/none.cfg bash "$S" run
[ ! -e "$W/not-mounted" ] && ok "Docker down AND appdata missing: still nothing created (array-stopped cron run)" || bad "created $W/not-mounted"
grep -q 'uts_path(.data.))' "$P/TrivyScanSettings.page" && ! grep -q '<code>/mnt/user/appdata' "$P/TrivyScanSettings.page" && ok "settings page shows the real data directory" || bad "settings page hard-codes the data path"

# ---------------------------------------------------------------- the report step runs out of memory
# On a 51-image server PHP hit Unraid's default memory_limit and, with Unraid's php.ini, printed nothing: the log said
# only "aggregate: ". Here a 16 MB Trivy result against a 16M limit.
OSD=$W/osdata/unraid-trivy-scan
printf 'version="7.3.4"\n' >"$OR/etc/unraid-version"
php -r '$v=[]; for($i=0;$i<40000;$i++) $v[]=["VulnerabilityID"=>"CVE-2024-".(10000+$i),"PkgName"=>"p$i","InstalledVersion"=>"1","Severity"=>"HIGH","Title"=>str_repeat("x",300)];
        file_put_contents($argv[1], json_encode(["SchemaVersion"=>2,"Results"=>[["Target"=>"t","Vulnerabilities"=>$v]]]));' "$W/big.json"
FAKE_OS_JSON=$W/big.json UTS_AGG_MEMORY=16M osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ "$(sed -n 's/^result=//p' "$OSD/report/last-run")" = failed ] && grep -q 'aggregate failed (exit 255):.*PHP fatal error: Allowed memory size' "$W/os.log" \
  && [ -f "$OSD/work-failed/os/result" ] && grep -q "to retry the report: .*aggregate.php $OSD/work-failed" "$W/os.log" \
  && ok "report step out of memory: reason logged, scan results kept in work-failed with a retry command" || bad "aggregate failure: $(tail -3 "$W/os.log")"
FAKE_OS_JSON=$W/big.json osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ ! -e "$OSD/work-failed" ] && grep -q 'report: cves=40000 .*peak_memory_mb=' "$W/os.log" && [ "$(sed -n 's/^result=//p' "$OSD/report/last-run")" = ok ] \
  && ok "same results with the default limit: report built, peak memory logged, work-failed removed" || bad "after failure: $(tail -3 "$W/os.log")"

# Header tabs (Menu="Tasks:n"): Unraid labels them with the page's Name, else the upper-cased file name
# (read on a 7.3.4 server: dynamix/include/DefaultPageLayout/Navigation/Main.php:23 `_(_var($button, 'Name', $pageName))`).
# 2026.11.01c shipped TrivyScanTab.page without Name and showed "TRIVYSCANTAB". The browser title (DefaultPageLayout.php:
# <title>NAME/$myPage['name']</title>) and the URL still use the file name, so up to 2026.11.02 the selected tab read
# "Tower/TrivyScanTab"; the file is now named after the label.
for f in "$P"/*.page; do
  if grep -Eq '^Menu="Tasks(:[0-9]+)?"' "$f"; then
    grep -Eq '^Name="[A-Za-z][A-Za-z ]+"$' "$f" && ok "Tasks page $(basename "$f") has a Name (header tab label)" || bad "Tasks page $(basename "$f") has no Name: the tab would show the file name"
    nm=$(sed -n 's/^Name="\(.*\)"$/\1/p' "$f")
    [ "$(basename "$f" .page)" = "${nm// /}" ] && ok "Tasks page file name matches its Name ($nm): browser title and URL read the same" || bad "Tasks page $(basename "$f") is not named after its Name '$nm'"
  fi
done
[ ! -e "$P/TrivyScanTab.page" ] && ! grep -rq 'TrivyScanTab' "$P" && ok "no reference to the old TrivyScanTab page name left" || bad "TrivyScanTab still referenced"

# ---------------------------------------------------------------- .plg lifecycle
PLG=$HERE/unraid-trivy-scan.plg
INST=$(php -r '$d=new DOMDocument(); $d->substituteEntities=true; $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) { if ($f->getAttribute("Method")==="remove") continue; foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent, "\n"; }' "$PLG")
REM=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) if ($f->getAttribute("Method")==="remove") foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent;' "$PLG")
grep -Eq 'trivy-scan (start|run|cron|update-db)|docker (pull|run)' <<<"$INST" && bad "install/boot block starts a scan or a download" || ok "install/boot blocks never scan or download"
grep -q 'trivy-scan stop' <<<"$INST" && grep -q 'trivy-scan apply' <<<"$INST" && ok "pre-install stops a running scan, post-install only applies cron" || bad "install block stop/apply"
grep -q 'trivy-scan uninstall' <<<"$REM" && ok "remove block runs uninstall (stop, cron, optional cleanup)" || bad "remove block"
grep -q 'case $f in \*/unraid-trivy-scan-2026[^)]*-x86_64-1.txz) ;;' <<<"$INST" && ok "old-package cleanup keeps the version being installed" || bad "package cleanup not version-preserving"
grep -q 'pluginURL="&pluginURL;"' "$PLG" && grep -q '<!ENTITY gitURL    "https://raw.githubusercontent.com/luuvasara/unraid-trivy-scan/main">' "$PLG" \
  && grep -q '<!ENTITY pluginURL "&gitURL;/&name;.plg">' "$PLG" && ok "pluginURL = .../luuvasara/unraid-trivy-scan/main/unraid-trivy-scan.plg" || bad "pluginURL"
VER=$(sed -n 's/^ *<!ENTITY version *"\([^"]*\)">.*/\1/p' "$PLG")
[[ $VER =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] && ok "version $VER is YYYY.MM.DD[a-z]" || bad "version $VER"
MD5=$(sed -n 's/^ *<!ENTITY md5 *"\([^"]*\)">.*/\1/p' "$PLG"); PKG=$HERE/packages/unraid-trivy-scan-$VER-x86_64-1.txz
[ -f "$PKG" ] && [ "$(md5sum <"$PKG" | cut -d' ' -f1)" = "$MD5" ] && [ "$(cut -d' ' -f1 "$PKG.md5")" = "$MD5" ] \
  && ok "package and .md5 match the .plg &md5;" || bad "package md5 (run ./build.sh)"
cmp -s <(tar -xJOf "$PKG" ./usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan) "$S" && ok "package contains the current scripts/trivy-scan" || bad "package is stale (run ./build.sh)"
[ -x "$P/event/stopping_docker" ] && ok "event/stopping_docker is executable in the tree (emhttp_event runs only executable files)" || bad "event/stopping_docker not executable"
grep -q 'chmod 755 /usr/local/emhttp/plugins/unraid-trivy-scan/event/stopping_docker' <<<"$INST" && ok "post-install sets 755 on the event script" || bad "post-install does not chmod the event script"
PKG_LIST=$(tar -tJvf "$PKG")   # list first: "tar | grep -q" under pipefail fails at random when grep exits early (SIGPIPE)
grep -q '^-rwxr-xr-x 0/0 .* ./usr/local/emhttp/plugins/unraid-trivy-scan/event/stopping_docker$' <<<"$PKG_LIST" \
  && ok "package ships event/stopping_docker as -rwxr-xr-x root/root" || bad "package lacks an executable event/stopping_docker: $(tar -tJvf "$PKG" | grep event)"
grep -c 'TRIVY_IMAGE=' "$S" | grep -qx 1 && ! grep -rq 'aquasec/trivy:' "$P" --include=*.php --include=*.page && ok "the Trivy image is named in exactly one place" || bad "Trivy image named in more than one place"

# ---------------------------------------------------------------- aggregate on fixture Trivy JSON
php "$HERE/tests/aggregate-test.php" "$HERE" || fail=1

# Every literal status message must survive clean() (scripts/trivy-scan), which turns any other character into '?':
# 2026.11.02 showed "scan stopped before it finished? the previous report is kept" because of a ';'.
bad_msgs=$(grep -oE 'last_run [a-z]+ "[^"$]*"' "$S" | sed -E 's/^last_run [a-z]+ "(.*)"$/\1/' | LC_ALL=C grep -n "[^A-Za-z0-9._/:@ ()+,=-]")
[ -z "$bad_msgs" ] && ok "status messages contain only characters clean() keeps" || bad "status messages clean() would mangle: $bad_msgs"
exit $fail
