#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# unit.sh - offline unit tests. A fake `docker` on PATH records calls, so no real container or image is touched.
# Covers: cron validation (bash and PHP agree on every case), the settings reader (bash and PHP) against hostile
# files, include/validate.php in update.php's scope, `apply` (cron only for a valid schedule), `uninstall` guards,
# the .plg lifecycle rules, and include/aggregate.php on fixture Trivy JSON (tests/aggregate-test.php).
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-cve-lens
S=$P/scripts/cve-lens
W=$HERE/tests/.work/unit; rm -rf "$W"; mkdir -p "$W/bin"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }

cat >"$W/bin/docker" <<EOF
#!/bin/sh
echo "docker \$*" >>"$W/docker.log"
case "\$1" in ps) exit 0 ;; info) exit 0 ;; esac
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_JSON:-}" ] && [ -z "\${FAKE_OS_FAIL:-}" ] && { cat "\$FAKE_OS_JSON"; exit 0; } ;; esac   # a large Trivy result
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_FAIL:-}" ] && { echo "FATAL fake failure" >&2; exit 1; }; echo '{"SchemaVersion":2,"Results":[]}' ;; esac
case " \$* " in *" db update "*)   # Grype DB download: with FAKE_GRYPE_DB=1, leave a DB in the directory mounted at /db
  [ -n "\${FAKE_GRYPE_DB:-}" ] && for a in "\$@"; do case "\$a" in *:/db) mkdir -p "\${a%:/db}/6" && echo x >"\${a%:/db}/6/vulnerability.db" ;; esac; done ;; esac
case " \$* " in *" sbom:/in/os.cdx.json "*)
  for a in "\$@"; do case "\$a" in *:/in/os.cdx.json:ro) cp "\${a%:/in/os.cdx.json:ro}" "$W/last-sbom.json" ;; esac; done
  [ -n "\${FAKE_GRYPE_FAIL:-}" ] && { echo "ERROR fake grype failure" >&2; exit 1; }
  cat "$W/grype.json" 2>/dev/null || echo '{"matches":[]}' ;; esac
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
JAVA_DB_KEEP=yes
NOTIFY=no
OS_KERNEL_MATCH=no
OS_PKG_DB_KEEP=yes
OS_PKG_MATCH=yes
OS_SCAN=yes
REGISTRY_AUTH=no
REGISTRY_CHECK=yes
REMOVE_DATA=no
SCHEDULE=
SCOPE=running
SHOW_TAB=yes
TIMEOUT=60
TRIVY_DB_KEEP=yes'
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
[ "$DEF_SH" = "$DEF_PHP" ] && ok "defaults identical in scripts/cve-lens and include/lib.php" || bad "defaults differ: $(tr '\n' ' ' <<<"$DEF_SH") vs $(tr '\n' ' ' <<<"$DEF_PHP")"
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
[ "$(grep -v '^#' "$UTS_CRON_FILE")" = "15 4 * * 1 /usr/local/emhttp/plugins/unraid-cve-lens/scripts/cve-lens cron >/dev/null 2>&1" ] \
  && [ -s "$W/update_cron.log" ] && ok "apply: valid schedule -> cron file + update_cron" || bad "apply valid: $(cat "$UTS_CRON_FILE" 2>&1)"
printf 'SCHEDULE="15 4 * * 1\n* * * * * touch %s/PWN5"\n' "$W" >"$W/a.cfg"
UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: invalid (multi-line) schedule -> no cron file" || bad "apply invalid wrote: $(cat "$UTS_CRON_FILE")"
printf 'SCHEDULE=""\n' >"$W/a.cfg"; UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: empty schedule -> no cron file" || bad "apply empty"
grep -q 'docker run\|docker pull' "$W/docker.log" 2>/dev/null && bad "apply/config touched docker run/pull" || ok "apply and config never run or pull an image"

# ---------------------------------------------------------------- uninstall guards
: >"$W/docker.log"
mkdir -p "$W/d1/unraid-cve-lens/cache" "$W/run"
printf 'REMOVE_DATA="yes"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d1/unraid-cve-lens UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ ! -e "$W/d1/unraid-cve-lens" ] && grep -q '^docker rmi aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c$' "$W/docker.log" \
  && ok "uninstall REMOVE_DATA=yes: data dir removed, docker rmi of the pinned reference only" || bad "uninstall yes: $(cat "$W/docker.log")"
mkdir -p "$W/d2/other"; UTS_CFG=$W/u.cfg UTS_DATA=$W/d2/other UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d2/other" ] && ok "uninstall: refuses a data path not ending in /unraid-cve-lens" || bad "uninstall removed an unexpected path"
mkdir -p "$W/victim"; touch "$W/victim/keep"; mkdir -p "$W/d3"; ln -s "$W/victim" "$W/d3/unraid-cve-lens"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d3/unraid-cve-lens UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -e "$W/victim/keep" ] && ok "uninstall: a symlinked data dir is not followed" || bad "uninstall followed a symlink"
mkdir -p "$W/d4/unraid-cve-lens"; : >"$W/docker.log"; printf 'REMOVE_DATA="no"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d4/unraid-cve-lens UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d4/unraid-cve-lens" ] && ! grep -q rmi "$W/docker.log" && ok "uninstall REMOVE_DATA=no keeps data and image" || bad "uninstall no"
grep -q 'docker rm -f\|docker ps -aq --filter label=unraid-cve-lens=1' "$W/docker.log" && ok "uninstall stops only containers labelled unraid-cve-lens=1" || bad "uninstall label filter: $(cat "$W/docker.log")"

# ---------------------------------------------------------------- OS scan: what the OS container gets
# A fake Unraid root with the system dirs, the dirs that must never be mounted, a symlinked /opt pointing at /mnt and
# a hostile unraid-version. `run` goes through the real script and the real aggregator; only docker is fake.
OR=$W/osroot
mkdir -p "$OR"/usr/bin "$OR"/lib/modules "$OR"/lib64 "$OR"/bin "$OR"/sbin "$OR"/mnt/user "$OR"/boot "$OR"/proc "$OR"/sys \
         "$OR"/etc "$OR"/var/lib/docker "$OR"/var/lib/pkgtools/packages "$W/osdata/unraid-cve-lens/cache/db" "$W/osrun"
ln -sfn "$OR/mnt" "$OR/opt"
touch "$OR/var/lib/pkgtools/packages/bash-5.3.003-x86_64-1" "$OR/var/lib/pkgtools/packages/docker-29.8.2-x86_64-1_LT"
echo x >"$W/osdata/unraid-cve-lens/cache/db/trivy.db"
osrun() {   # osrun <cfg lines...>: one offline `run` with the fake docker and the fake root
  printf '%s\n' "$@" >"$W/os.cfg"; : >"$W/docker.log"
  UTS_CFG=$W/os.cfg UTS_DATA=$W/osdata/unraid-cve-lens UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_OS_ROOT=$OR \
    UTS_OS_KERNEL=6.18.58-Unraid UTS_PLUGIN_DIR=$P UTS_NOTIFY=$W/none UTS_CRON_FILE=$W/os.cron bash "$S" run
}
printf 'version="7.3.4"\n' >"$OR/etc/unraid-version"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' && ok "run with OS_SCAN=yes (fake docker) exits 0" || bad "OS run rc=$?: $(tail -3 "$W/os.log")"
OSL=$(grep -- '--label unraid-cve-lens.role=os' "$W/docker.log")
[ "$(grep -c . <<<"$OSL")" = 1 ] && ok "one OS scanner container" || bad "OS containers: $OSL"
grep -q -- '--cap-drop ALL --security-opt no-new-privileges --network none' <<<"$OSL" && ok "OS container: --cap-drop ALL, no-new-privileges, --network none" || bad "OS hardening: $OSL"
grep -q 'docker.sock' <<<"$OSL" && bad "OS container got the Docker socket" || ok "OS container has no Docker socket"
TG=$(grep -o 'target=/rootfs/[a-z0-9]*,readonly,bind-recursive=disabled' <<<"$OSL" | sed 's/^target=\/rootfs\///; s/,.*//' | sort | tr '\n' ' ')
[ "$TG" = "bin lib lib64 sbin usr " ] && ok "OS mounts: exactly /usr /lib /lib64 /bin /sbin, read-only, non-recursive (symlinked /opt skipped)" || bad "OS mounts: '$TG'"
[ "$(grep -o -- '--mount' <<<"$OSL" | wc -l)" = 5 ] && [ "$(grep -o -- ' -v ' <<<"$OSL" | wc -l)" = 1 ] && grep -q -- "-v $W/osdata/unraid-cve-lens/cache:/cache:ro" <<<"$OSL" \
  && ok "OS container: 5 mounts plus the DB read-only, nothing else" || bad "OS extra mounts: $OSL"
grep -qE "source=$OR/(mnt|boot|proc|sys|etc|var|dev|root|opt)|source=/(mnt|boot|proc|sys|etc|var)" <<<"$OSL" && bad "a forbidden directory was mounted" \
  || ok "never mounted: /mnt /boot /proc /sys /etc /var (incl. /var/lib/docker) /opt-symlink"
grep -q -- 'rootfs --cache-dir /cache .*--offline-scan --scanners vuln .*--skip-dirs /rootfs/lib/modules .* /rootfs$' <<<"$OSL" \
  && ok "OS scan: trivy rootfs /rootfs, offline, vuln only, /lib/modules skipped" || bad "OS trivy args: $OSL"
osrep() { php -r '$r=json_decode(file_get_contents($argv[1]),true); echo eval("return ".$argv[2].";"), "\n";' "$W/osdata/unraid-cve-lens/report/report.json" "$1"; }
[ "$(osrep '$r["images"][0]["kind"]." ".$r["images"][0]["name"]." ".$r["summary"]["os"]')" = "os Unraid OS 7.3.4 ok" ] && ok "report: OS target 'Unraid OS 7.3.4', scanned" || bad "report OS: $(osrep 'json_encode($r["images"])')"
[ "$(osrep 'json_encode([$r["host"]["kernel"], $r["host"]["packages"]])')" = '["6.18.58-Unraid",[["bash","5.3.003","1"],["docker","29.8.2","1_LT"]]]' ] \
  && ok "report: kernel and the Slackware package list read on the host" || bad "report host: $(osrep 'json_encode($r["host"])')"
[ "$(sed -n 's/^message=//p' "$W/osdata/unraid-cve-lens/report/last-run")" = "0 image(s) and the Unraid OS scanned, 0 failed" ] && ok "last-run message names the OS" || bad "last-run: $(cat "$W/osdata/unraid-cve-lens/report/last-run")"
printf 'version="$(touch %s/PWN6)"\n' "$W" >"$OR/etc/unraid-version"
FAKE_OS_FAIL=1 osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ ! -e "$W/PWN6" ] && [ "$(osrep '$r["images"][0]["name"]')" = "Unraid OS unknown" ] && ok "hostile unraid-version: not executed, shown as 'unknown'" || bad "hostile unraid-version"
[ "$(osrep '$r["images"][0]["scan"]." ".$r["images"][0]["error"]')" = "failed FATAL fake failure" ] && [ "$(sed -n 's/^message=//p' "$W/osdata/unraid-cve-lens/report/last-run")" = "0 image(s) and the Unraid OS scanned, 1 failed" ] \
  && ok "failed OS scan: listed with Trivy's error line, counted as failed" || bad "OS failure: $(osrep 'json_encode($r["images"])')"
osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
grep -q 'role=os' "$W/docker.log" && bad "OS_SCAN=no still ran an OS container" || ok "OS_SCAN=no: no OS container"
[ "$(osrep 'json_encode($r["host"])." ".$r["summary"]["os"]')" = "null off" ] && ok "OS_SCAN=no: no OS target in the report" || bad "OS_SCAN=no report"

# ---------------------------------------------------------------- keeping the Trivy databases, sizes for the settings page
OSD=$W/osdata/unraid-cve-lens
mkdir -p "$OSD/cache/java-db"; echo javadb >"$OSD/cache/java-db/trivy-java.db"
osrun 'OS_SCAN="no"' 'JAVA_DB="yes"' 'TRIVY_DB_KEEP="yes"' 'JAVA_DB_KEEP="yes"'
[ -f "$OSD/cache/db/trivy.db" ] && [ -f "$OSD/cache/java-db/trivy-java.db" ] && ok "TRIVY_DB_KEEP=yes, JAVA_DB_KEEP=yes: both stay after the scan" || bad "kept Trivy DBs removed"
SZ=$(UTS_DATA=$OSD bash "$S" db-sizes)
grep -qE '^trivy_now=[0-9]+$' <<<"$SZ" && grep -qE '^java_now=[0-9]+$' <<<"$SZ" && grep -qE '^trivy_last=[0-9]+$' <<<"$SZ" \
  && ok "db-sizes: size on disk for present DBs, size at last download noted" || bad "db-sizes: $SZ"
osrun 'OS_SCAN="no"' 'JAVA_DB="yes"' 'TRIVY_DB_KEEP="no"' 'JAVA_DB_KEEP="no"' && [ "$(sed -n 's/^result=//p' "$OSD/report/last-run")" = ok ] \
  && [ ! -e "$OSD/cache/db" ] && [ ! -e "$OSD/cache/java-db" ] && [ -d "$OSD/cache" ] \
  && ok "TRIVY_DB_KEEP=no, JAVA_DB_KEEP=no: scan works, both deleted when it ends" || bad "unkept Trivy DBs: $(ls -R "$OSD/cache")"
SZ=$(UTS_DATA=$OSD bash "$S" db-sizes)
! grep -q '^trivy_now' <<<"$SZ" && grep -qE '^trivy_last=[0-9]+$' <<<"$SZ" && grep -qE '^java_last=[0-9]+$' <<<"$SZ" \
  && ok "db-sizes: not on disk, last download size still reported" || bad "db-sizes after delete: $SZ"
: >"$W/docker.log"; printf '%s\n' 'TRIVY_DB_KEEP="no"' 'JAVA_DB_KEEP="no"' 'OS_SCAN="no"' >"$W/os.cfg"
UTS_CFG=$W/os.cfg UTS_DATA=$OSD UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_PLUGIN_DIR=$P bash "$S" update-db --foreground; RC=$?
[ "$RC" = 0 ] && ! grep -q 'download-db-only\|download-java-db-only' "$W/docker.log" && ok "update-db with nothing kept: no download, success" || bad "update-db nothing kept: rc=$RC $(cat "$W/docker.log")"
mkdir -p "$OSD/cache/db"; echo x >"$OSD/cache/db/trivy.db"
mkdir -p "$W/victim2"; touch "$W/victim2/keep"; rm -rf "$OSD/cache/java-db"; ln -s "$W/victim2" "$OSD/cache/java-db"
osrun 'OS_SCAN="no"' 'JAVA_DB="yes"' 'JAVA_DB_KEEP="no"'
[ -e "$W/victim2/keep" ] && ok "JAVA_DB_KEEP=no: a symlinked java-db is not followed or emptied" || bad "followed a java-db symlink"
rm -f "$OSD/cache/java-db"
php -r 'require $argv[1]; $s = uts_db_sizes("trivy_now=1700000\njava_last=2048\nevil_now=1\ntrivy_now=x\n"); echo uts_db_size($s,"trivy","1.6 GB"), "|", uts_db_size($s,"java","1.5 GB"), "\n";' "$P/include/lib.php" \
  | grep -qx 'On disk: 1.6 GB|Not on disk now; 2 MB at its last download' && ok "settings page size texts: on disk / last download; junk lines ignored" || bad "size texts"
php -r 'require $argv[1]; echo uts_db_size([], "java", "1.5 GB"), "\n";' "$P/include/lib.php" | grep -qx 'Not downloaded yet; about 1.5 GB (estimate)' && ok "settings page size text: estimate when never downloaded" || bad "estimate text"

# ---------------------------------------------------------------- OS packages against NVD CPEs (Grype)
OSD=$W/osdata/unraid-cve-lens
GDB=$OSD/grype-run   # OS_PKG_DB_KEEP=no: per-run DB (the default is yes, like the Trivy databases)
printf 'version="7.3.4"\n' >"$OR/etc/unraid-version"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_MATCH="yes"' 'OS_PKG_DB_KEEP="no"'
[ "$(osrep '$r["host"]["pkg_match"]." ".$r["host"]["pkg_error"]')" = "failed no OS package database (Grype DB download failed)" ] \
  && ! grep -q 'role=pkgmatch' "$W/docker.log" && ok "no Grype DB: no match container, the report says why" || bad "no Grype DB: $(osrep 'json_encode($r["host"])')"
export FAKE_GRYPE_DB=1
cp "$HERE/tests/fixtures/ospkg/os/pkgmatch.json" "$W/grype.json"
printf 'CVE-2025-9002 samba # test\n' >"$W/os-ignore.txt"   # next to the settings file ($W/os.cfg)
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_MATCH="yes"' 'OS_PKG_DB_KEEP="no"' && ok "run with the OS package match exits 0" || bad "pkg run: $(tail -3 "$W/os.log")"
PL=$(grep -- '--label unraid-cve-lens.role=pkgmatch' "$W/docker.log")
[ "$(grep -c . <<<"$PL")" = 1 ] && grep -q -- "anchore/grype:v[0-9.]*@sha256:[0-9a-f]\{64\} sbom:/in/os.cdx.json -o json --by-cve -q$" <<<"$PL" \
  && ok "one match container: pinned Grype, sbom:/in/os.cdx.json, JSON" || bad "pkgmatch container: $PL"
grep -q -- "--cap-drop ALL --security-opt no-new-privileges --user $(id -u):$(id -g) --network none --read-only" <<<"$PL" && ! grep -q 'docker.sock\|--mount' <<<"$PL" \
  && ok "match container: as the DB owner (Grype makes the DB dir mode 700), no network, read-only, no socket, no host directories" || bad "pkgmatch hardening: $PL"
[ "$(grep -o -- ' -v [^ ]*' <<<"$PL" | sed 's/^ -v //' | sort | tr '\n' ' ')" = "$GDB:/db:ro $W/osdata/unraid-cve-lens/work/os/os.cdx.json:/in/os.cdx.json:ro " ] \
  && ok "match container gets exactly the Grype DB (read-only) and the SBOM (read-only)" || bad "pkgmatch mounts: $(grep -o -- ' -v [^ ]*' <<<"$PL")"
GL=$(grep -- 'role=db' "$W/docker.log" | grep 'anchore/grype')
grep -q -- "-v $GDB:/db anchore/grype:.* db update$" <<<"$GL" && ! grep -q 'docker.sock\|--network none' <<<"$GL" \
  && ok "Grype DB download: db role, network, no socket, writes only $GDB" || bad "grype db container: $GL"
[ ! -e "$GDB" ] && [ ! -e "$OSD/grype" ] && ok "OS_PKG_DB_KEEP=no: the per-run Grype DB is deleted when the scan ends, nothing kept" || bad "per-run grype DB left: $(ls "$OSD")"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_DB_KEEP="yes"'
grep -- 'role=db' "$W/docker.log" | grep -q -- "-v $OSD/grype:/db anchore/grype" && grep -- 'role=pkgmatch' "$W/docker.log" | grep -q -- "-v $OSD/grype:/db:ro " \
  && [ -f "$OSD/grype/6/vulnerability.db" ] && [ ! -e "$OSD/grype/tmp" ] && [ ! -e "$GDB" ] \
  && ok "OS_PKG_DB_KEEP=yes: DB downloaded into, kept in and mapped read-only from $OSD/grype" || bad "keep=yes: $(find "$OSD" | head -20)"
: >"$W/docker.log"
UTS_CFG=$W/os.cfg UTS_DATA=$OSD UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_PLUGIN_DIR=$P bash "$S" update-db --foreground
grep -q 'anchore/grype.* db update' "$W/docker.log" && ok "update-db with OS_PKG_DB_KEEP=yes refreshes the kept Grype DB" || bad "update-db keep=yes: $(cat "$W/docker.log")"
printf '%s\n' 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_DB_KEEP="no"' >"$W/os.cfg"; : >"$W/docker.log"
UTS_CFG=$W/os.cfg UTS_DATA=$OSD UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_PLUGIN_DIR=$P bash "$S" update-db --foreground
! grep -q 'anchore/grype' "$W/docker.log" && ok "update-db with OS_PKG_DB_KEEP=no skips Grype (nothing to keep)" || bad "update-db keep=no ran grype"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_DB_KEEP="no"'
[ ! -e "$OSD/grype" ] && [ ! -e "$GDB" ] && grep -q 'no longer kept' "$W/os.log" && ok "switching OS_PKG_DB_KEEP off deletes the kept DB at the next scan" || bad "kept DB not removed: $(ls "$OSD")"
ln -s "$W/victim" "$OSD/grype-run"; osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_DB_KEEP="no"'
[ -e "$W/victim/keep" ] && [ ! -e "$W/victim/tmp" ] && [ ! -e "$W/victim/6" ] && ! grep -q 'role=pkgmatch' "$W/docker.log" \
  && ok "a symlink in place of the per-run DB dir is neither followed nor removed; match skipped" || bad "followed a grype-run symlink: $(ls "$W/victim")"
rm -f "$OSD/grype-run"
mkdir -p "$W/victim2/6"; echo x >"$W/victim2/6/vulnerability.db"; ln -s "$W/victim2" "$OSD/grype"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'   # default keep=yes, but the kept DB dir is a symlink
! grep -q 'role=pkgmatch' "$W/docker.log" && [ "$(osrep '$r["host"]["pkg_match"]')" = failed ] && [ -e "$W/victim2/6/vulnerability.db" ] \
  && ok "a symlink in place of the kept DB dir is not used either: no match container, report says failed" || bad "kept-DB symlink used: $(grep pkgmatch "$W/docker.log")"
rm -f "$OSD/grype"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'   # defaults: match on, DB kept
grep -- 'role=pkgmatch' "$W/docker.log" | grep -q -- "-v $OSD/grype:/db:ro " && ok "defaults: OS package match on, Grype DB kept in $OSD/grype" || bad "default grype DB: $(grep grype "$W/docker.log")"
[ "$(osrep '$r["host"]["pkg_match"]." ".$r["host"]["base"]." ".$r["host"]["mapped_count"]')" = "ok slackware 1" ] && ok "report: match ok, Slackware, 1 package mapped (bash)" || bad "pkg report host: $(osrep 'json_encode($r["host"])')"
[ "$(osrep 'implode(",", array_column($r["cves"], "id"))')" = "CVE-2025-9001,CVE-2025-9005,CVE-2025-9003,CVE-2025-9004" ] && ok "report: Grype CVEs on the OS target, os-ignore.txt next to the settings applied (9002 hidden)" || bad "pkg cves: $(osrep 'implode(",", array_column($r["cves"], "id"))')"
php -r '$b=json_decode(file_get_contents($argv[1]),true); exit(array_column($b["components"],"name")===["bash"] ? 0 : 1);' "$W/last-sbom.json" \
  && ok "SBOM: mapped packages only (bash; docker is left to the Trivy scan), no kernel by default" || bad "SBOM: $(cat "$W/last-sbom.json")"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_KERNEL_MATCH="yes"'
grep -q '"cpe:2.3:o:linux:linux_kernel:6.18.58:' "$W/last-sbom.json" && ok "OS_KERNEL_MATCH=yes: kernel 6.18.58 in the SBOM" || bad "kernel not in SBOM"
FAKE_GRYPE_FAIL=1 osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ "$(osrep '$r["host"]["pkg_match"]." ".$r["host"]["pkg_error"]." ".$r["images"][0]["scan"]')" = "failed ERROR fake grype failure ok" ] \
  && osrep 'implode("|",$r["warnings"])' | grep -q 'OS package CVE match failed: ERROR fake grype failure' \
  && ok "Grype failure: reason in the report and the warnings, the Trivy OS scan stays ok" || bad "grype fail: $(osrep 'json_encode($r["host"])')"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'OS_PKG_MATCH="no"'
! grep -q 'role=pkgmatch\|anchore/grype' "$W/docker.log" && [ "$(osrep '$r["host"]["pkg_match"]')" = off ] \
  && ok "OS_PKG_MATCH=no: no Grype pull, download or container; match off" || bad "OS_PKG_MATCH=no: $(grep grype "$W/docker.log")"
# RPM base (Unraid 8 / Fedora): no pkgtools, an RPM database and rpm(8)
rm -rf "$OR/var/lib/pkgtools"; mkdir -p "$OR/usr/lib/sysimage/rpm"
printf '#!/bin/sh\necho "rpm $*" >>%s/rpm.log\ncase "$*" in *CHANGELOGTEXT*) cat %s ;; *) cat %s ;; esac\n' "$W" \
  "$HERE/tests/fixtures/osinv/rpm/rpm-changelog.txt" "$HERE/tests/fixtures/osinv/rpm/rpm.tsv" >"$W/bin/fake-rpm"; chmod 755 "$W/bin/fake-rpm"
UTS_RPM=$W/bin/fake-rpm osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
grep -q -- "^rpm --root $OR -qa --qf" "$W/rpm.log" && ok "RPM base: rpm -qa --root <os root>" || bad "rpm call: $(cat "$W/rpm.log" 2>&1)"
[ "$(osrep '$r["host"]["base"]." ".$r["host"]["package_count"]." ".$r["host"]["mapped_count"]')" = "rpm 4 3" ] && ok "report: RPM base, 4 source packages, 3 mapped" || bad "rpm host: $(osrep 'json_encode($r["host"])')"
php -r '$b=json_decode(file_get_contents($argv[1]),true); $n=array_column($b["components"],"name"); sort($n); exit($n===["openssh","openssl","shadow-utils"] ? 0 : 1);' "$W/last-sbom.json" \
  && ok "RPM SBOM: openssh, openssl, shadow-utils" || bad "rpm SBOM: $(cat "$W/last-sbom.json")"
rm -rf "$OR/usr/lib/sysimage"
osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ "$(osrep '$r["host"]["pkg_error"]')" = "no package database found (neither Slackware pkgtools nor RPM)" ] && ok "no package database at all: reason in the report" || bad "no pkg db: $(osrep 'json_encode($r["host"])')"

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
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user/appdata/"\nDOCKER_APP_UNRAID_PATH=""\n
/mnt/cache/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/cache/appdata/"\n
/mnt/fast_pool/docker-appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH=/mnt/fast_pool/docker-appdata\n
/mnt/cache/b/unraid-cve-lens|A=1\nDOCKER_APP_CONFIG_PATH="/mnt/user/a"\nDOCKER_APP_CONFIG_PATH="/mnt/cache/b/"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_ENABLED="yes"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH=""\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/etc/appdata"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user/../../etc"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user/a b"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user/a:/b"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user/$(id)"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/"\n
/mnt/user/appdata/unraid-cve-lens|DOCKER_APP_CONFIG_PATH="/mnt/user//x"\n
CASES
[ "$(UTS_DOCKER_CFG=$W/nonexistent.cfg bash "$S" datadir)" = /mnt/user/appdata/unraid-cve-lens ] && ok "datadir: no docker.cfg -> /mnt/user/appdata/unraid-cve-lens" || bad "datadir without docker.cfg"
# array stopped / location missing: nothing is created, not even last-run (mkdir -p would build /mnt/... in RAM)
printf '#!/bin/sh\nexit 1\n' >"$W/bin/docker-down"; MISSING=$W/not-mounted/appdata
PATH="$W/bin:$PATH" UTS_DATA=$MISSING/unraid-cve-lens UTS_RUN=$W/run-miss UTS_LOG=$W/miss.log UTS_CFG=$W/none.cfg bash "$S" run
RC=$?
[ "$RC" = 1 ] && [ ! -e "$W/not-mounted" ] && grep -q 'does not exist' "$W/miss.log" && ok "missing appdata parent: scan refuses (rc 1), logs why, creates nothing" || bad "missing parent: rc=$RC, $(ls "$W/not-mounted" 2>&1), $(cat "$W/miss.log" 2>&1)"
FDOCK=$W/bin2; mkdir -p "$FDOCK"; printf '#!/bin/sh\nexit 1\n' >"$FDOCK/docker"; chmod 755 "$FDOCK/docker"
PATH="$FDOCK:$PATH" UTS_DATA=$MISSING/unraid-cve-lens UTS_RUN=$W/run-miss UTS_LOG=$W/miss.log UTS_CFG=$W/none.cfg bash "$S" run
[ ! -e "$W/not-mounted" ] && ok "Docker down AND appdata missing: still nothing created (array-stopped cron run)" || bad "created $W/not-mounted"
grep -q 'uts_path(.data.))' "$P/CveLensSettings.page" && ! grep -q '<code>/mnt/user/appdata' "$P/CveLensSettings.page" && ok "settings page shows the real data directory" || bad "settings page hard-codes the data path"

# ---------------------------------------------------------------- the report step runs out of memory
# On a 51-image server PHP hit Unraid's default memory_limit and, with Unraid's php.ini, printed nothing: the log said
# only "aggregate: ". Here a 16 MB Trivy result against a 16M limit.
OSD=$W/osdata/unraid-cve-lens
printf 'version="7.3.4"\n' >"$OR/etc/unraid-version"
php -r '$v=[]; for($i=0;$i<40000;$i++) $v[]=["VulnerabilityID"=>"CVE-2024-".(10000+$i),"PkgName"=>"p$i","InstalledVersion"=>"1","Severity"=>"HIGH","Title"=>str_repeat("x",300)];
        file_put_contents($argv[1], json_encode(["SchemaVersion"=>2,"Results"=>[["Target"=>"t","Vulnerabilities"=>$v]]]));' "$W/big.json"
FAKE_OS_JSON=$W/big.json UTS_AGG_MEMORY=16M osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ "$(sed -n 's/^result=//p' "$OSD/report/last-run")" = failed ] && grep -q 'aggregate failed (exit 255):.*PHP fatal error: Allowed memory size' "$W/os.log" \
  && [ -f "$OSD/work-failed/os/result" ] && grep -q "to retry the report: .*aggregate.php $OSD/work-failed $OSD/report/report.json scope=running registry=no trivy=[0-9.]*@sha256:[0-9a-f]* cache=$OSD/cache\$" "$W/os.log" \
  && ok "report step out of memory: reason logged, scan results kept in work-failed with a retry command" || bad "aggregate failure: $(tail -3 "$W/os.log")"
FAKE_OS_JSON=$W/big.json osrun 'OS_SCAN="yes"' 'JAVA_DB="no"'
[ ! -e "$OSD/work-failed" ] && grep -q 'report: cves=40000 .*peak_memory_mb=' "$W/os.log" && [ "$(sed -n 's/^result=//p' "$OSD/report/last-run")" = ok ] \
  && ok "same results with the default limit: report built, peak memory logged, work-failed removed" || bad "after failure: $(tail -3 "$W/os.log")"

# Header tabs (Menu="Tasks:n"): Unraid labels them with the page's Name, else the upper-cased file name
# (read on a 7.3.4 server: dynamix/include/DefaultPageLayout/Navigation/Main.php:23 `_(_var($button, 'Name', $pageName))`).
# 2026.11.01c shipped TrivyScanTab.page without Name and showed "TRIVYSCANTAB". The browser title (DefaultPageLayout.php:   # keep-old-name
# <title>NAME/$myPage['name']</title>) and the URL still use the file name, so up to 2026.11.02 the selected tab read
# "Tower/TrivyScanTab"; the file is now named after the label.   # keep-old-name
for f in "$P"/*.page; do
  if grep -Eq '^Menu="Tasks(:[0-9]+)?"' "$f"; then
    grep -Eq '^Name="[A-Za-z][A-Za-z ]+"$' "$f" && ok "Tasks page $(basename "$f") has a Name (header tab label)" || bad "Tasks page $(basename "$f") has no Name: the tab would show the file name"
    nm=$(sed -n 's/^Name="\(.*\)"$/\1/p' "$f")
    [ "$(basename "$f" .page)" = "${nm// /}" ] && ok "Tasks page file name matches its Name ($nm): browser title and URL read the same" || bad "Tasks page $(basename "$f") is not named after its Name '$nm'"
  fi
done
[ ! -e "$P/TrivyScanTab.page" ] && ! grep -rq 'TrivyScanTab' "$P" && ok "no reference to the old TrivyScanTab page name left" || bad "TrivyScanTab still referenced"   # keep-old-name

# ---------------------------------------------------------------- .plg lifecycle
PLG=$HERE/unraid-cve-lens.plg
INST=$(php -r '$d=new DOMDocument(); $d->substituteEntities=true; $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) { if ($f->getAttribute("Method")==="remove") continue; foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent, "\n"; }' "$PLG")
REM=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) if ($f->getAttribute("Method")==="remove") foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent;' "$PLG")
grep -Eq 'cve-lens (start|run|cron|update-db)|docker (pull|run)' <<<"$INST" && bad "install/boot block starts a scan or a download" || ok "install/boot blocks never scan or download"
grep -q 'cve-lens stop' <<<"$INST" && grep -q 'cve-lens apply' <<<"$INST" && ok "pre-install stops a running scan, post-install only applies cron" || bad "install block stop/apply"
grep -q 'cve-lens uninstall' <<<"$REM" && ok "remove block runs uninstall (stop, cron, optional cleanup)" || bad "remove block"
grep -q 'case $f in \*/unraid-cve-lens-2026[^)]*-x86_64-1.txz) ;;' <<<"$INST" && ok "old-package cleanup keeps the version being installed" || bad "package cleanup not version-preserving"
grep -q 'pluginURL="&pluginURL;"' "$PLG" && grep -q '<!ENTITY gitURL    "https://raw.githubusercontent.com/luuvasara/unraid-trivy-scan/main">' "$PLG" \
  && grep -q '<!ENTITY pluginURL "&gitURL;/&name;.plg">' "$PLG" && ok "pluginURL = .../luuvasara/unraid-trivy-scan/main/unraid-cve-lens.plg" || bad "pluginURL"
VER=$(sed -n 's/^ *<!ENTITY version *"\([^"]*\)">.*/\1/p' "$PLG")
[[ $VER =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] && ok "version $VER is YYYY.MM.DD[a-z]" || bad "version $VER"
MD5=$(sed -n 's/^ *<!ENTITY md5 *"\([^"]*\)">.*/\1/p' "$PLG"); PKG=$HERE/packages/unraid-cve-lens-$VER-x86_64-1.txz
[ -f "$PKG" ] && [ "$(md5sum <"$PKG" | cut -d' ' -f1)" = "$MD5" ] && [ "$(cut -d' ' -f1 "$PKG.md5")" = "$MD5" ] \
  && ok "package and .md5 match the .plg &md5;" || bad "package md5 (run ./build.sh)"
cmp -s <(tar -xJOf "$PKG" ./usr/local/emhttp/plugins/unraid-cve-lens/scripts/cve-lens) "$S" && ok "package contains the current scripts/cve-lens" || bad "package is stale (run ./build.sh)"
[ -x "$P/event/stopping_docker" ] && ok "event/stopping_docker is executable in the tree (emhttp_event runs only executable files)" || bad "event/stopping_docker not executable"
grep -q 'chmod 755 /usr/local/emhttp/plugins/unraid-cve-lens/event/stopping_docker' <<<"$INST" && ok "post-install sets 755 on the event script" || bad "post-install does not chmod the event script"
PKG_LIST=$(tar -tJvf "$PKG")   # list first: "tar | grep -q" under pipefail fails at random when grep exits early (SIGPIPE)
grep -q '^-rwxr-xr-x 0/0 .* ./usr/local/emhttp/plugins/unraid-cve-lens/event/stopping_docker$' <<<"$PKG_LIST" \
  && ok "package ships event/stopping_docker as -rwxr-xr-x root/root" || bad "package lacks an executable event/stopping_docker: $(tar -tJvf "$PKG" | grep event)"
grep -c 'TRIVY_IMAGE=' "$S" | grep -qx 1 && ! grep -rq 'aquasec/trivy:' "$P" --include=*.php --include=*.page && ok "the Trivy image is named in exactly one place" || bad "Trivy image named in more than one place"

# ---------------------------------------------------------------- aggregate on fixture Trivy JSON
php "$HERE/tests/aggregate-test.php" "$HERE" || fail=1
php "$HERE/tests/osinventory-test.php" "$HERE" || fail=1
grep -c 'GRYPE_IMAGE=' "$S" | grep -qx 1 && ! grep -rq 'anchore/grype:' "$P" --include=*.php --include=*.page && ok "the Grype image is named in exactly one place" || bad "Grype image named in more than one place"

# Every literal status message must survive clean() (scripts/cve-lens), which turns any other character into '?':
# 2026.11.02 showed "scan stopped before it finished? the previous report is kept" because of a ';'.
bad_msgs=$(grep -oE 'last_run [a-z]+ "[^"$]*"' "$S" | sed -E 's/^last_run [a-z]+ "(.*)"$/\1/' | LC_ALL=C grep -n "[^A-Za-z0-9._/:@ ()+,=-]")
[ -z "$bad_msgs" ] && ok "status messages contain only characters clean() keeps" || bad "status messages clean() would mangle: $bad_msgs"

# keep-old-begin
# ---------------------------------------------------------------- migration from "Trivy Scan" (unraid-trivy-scan)
MIG=$P/scripts/migrate-from-trivy-scan
M=$W/mig; rm -rf "$M"; mkdir -p "$M/bin2"
cat >"$M/bin2/docker" <<EOF
#!/bin/sh
echo "docker \$*" >>"$M/docker.log"
case " \$* " in *" ps "*"label=unraid-trivy-scan=1"*) echo abc123 ;; esac
exit 0
EOF
chmod 755 "$M/bin2/docker"
printf '#!/bin/sh\necho update_cron >>"%s/cron.log"\n' "$M" >"$M/update_cron"; chmod 755 "$M/update_cron"
mig() {   # mig <mode> [appdata dir]: run the migration against the fake tree under $M
  PATH="$M/bin2:$PATH" UTS_OLD_FLASH=$M/flash/unraid-trivy-scan UTS_NEW_FLASH=$M/flash/unraid-cve-lens UTS_OLD_RUN=$M/oldrun \
    UTS_OLD_PLUGIN_DIR=$M/nonexistent UTS_UPDATE_CRON=$M/update_cron UTS_CVELENS=$S UTS_DATA=${2:-$M/appdata}/unraid-cve-lens bash "$MIG" "${1:-all}"
}
mkdir -p "$M/flash/unraid-trivy-scan" "$M/appdata/unraid-trivy-scan/cache/db" "$M/appdata/unraid-trivy-scan/report"
printf 'SCHEDULE="15 4 * * 1"\nSCOPE="all"\n' >"$M/flash/unraid-trivy-scan/unraid-trivy-scan.cfg"
printf '# unraid-trivy-scan: scheduled scan\n15 4 * * 1 /usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan cron >/dev/null 2>&1\n' >"$M/flash/unraid-trivy-scan/unraid-trivy-scan.cron"
echo CVE-2020-0001 >"$M/flash/unraid-trivy-scan/os-ignore.txt"; echo "x y" >"$M/flash/unraid-trivy-scan/cpe-map.txt"; echo img >"$M/flash/unraid-trivy-scan/ignore.txt"
echo db >"$M/appdata/unraid-trivy-scan/cache/db/trivy.db"; echo '{}' >"$M/appdata/unraid-trivy-scan/report/report.json"
mig all >"$M/run1.out" 2>&1; rc=$?
F=$M/flash/unraid-cve-lens
[ $rc = 0 ] && [ "$(cat "$F/unraid-cve-lens.cfg")" = "$(cat "$M/flash/unraid-trivy-scan/unraid-trivy-scan.cfg")" ] && [ "$(cat "$F/os-ignore.txt")" = CVE-2020-0001 ] \
  && [ -f "$F/cpe-map.txt" ] && [ -f "$F/ignore.txt" ] && ok "migration: cfg, os-ignore, cpe-map and ignore.txt are copied to the new flash folder" || bad "migration copy: rc=$rc $(cat "$M/run1.out"); $(printf "%s " "$F"/*)"
[ "$(grep -v '^#' "$F/unraid-cve-lens.cron")" = "15 4 * * 1 /usr/local/emhttp/plugins/unraid-cve-lens/scripts/cve-lens cron >/dev/null 2>&1" ] \
  && ! grep -q 'trivy-scan' "$F/unraid-cve-lens.cron" && ok "migration: the schedule is copied with the command path rewritten" || bad "migration cron: $(cat "$F/unraid-cve-lens.cron")"
[ -f "$M/flash/unraid-trivy-scan/unraid-trivy-scan.cfg" ] && [ ! -e "$M/flash/unraid-trivy-scan/unraid-trivy-scan.cron" ] && [ -f "$M/flash/unraid-trivy-scan/unraid-trivy-scan.cron.migrated" ] \
  && grep -q update_cron "$M/cron.log" && ok "migration: old flash folder kept, old schedule renamed out of update_cron's glob and cron refreshed" || bad "migration old cron"
[ ! -e "$M/appdata/unraid-trivy-scan" ] && [ "$(cat "$M/appdata/unraid-cve-lens/cache/db/trivy.db")" = db ] && [ -f "$M/appdata/unraid-cve-lens/report/report.json" ] \
  && ok "migration: data folder moved (not copied) with its databases and report" || bad "migration data move: $(find "$M/appdata" -maxdepth 1)"
grep -q 'docker ps -aq --filter label=unraid-trivy-scan=1' "$M/docker.log" && grep -q 'docker rm -f abc123' "$M/docker.log" \
  && ok "migration: containers with the OLD label are removed" || bad "migration old-label cleanup: $(cat "$M/docker.log")"
# idempotent: a second run changes nothing, and never overwrites what the user changed since
echo 'SCHEDULE=""' >"$F/unraid-cve-lens.cfg"; before=$(cd "$M" && find flash appdata -type f -exec md5sum {} + | sort)
mig all >"$M/run2.out" 2>&1; rc=$?; after=$(cd "$M" && find flash appdata -type f -exec md5sum {} + | sort)
[ $rc = 0 ] && [ "$(cat "$F/unraid-cve-lens.cfg")" = 'SCHEDULE=""' ] && [ -d "$M/appdata/unraid-cve-lens" ] && [ ! -e "$M/appdata/unraid-trivy-scan" ] && [ "$before" = "$after" ] \
  && ok "migration: second run is a no-op (settings the user changed are not overwritten)" || bad "migration idempotency: rc=$rc $(cat "$M/run2.out")"
# symlink guard: an old data folder that is a symlink is never moved or followed
mkdir -p "$M/victim"; echo keep >"$M/victim/keep"; mkdir -p "$M/app-sym"; ln -s "$M/victim" "$M/app-sym/unraid-trivy-scan"
mig data "$M/app-sym" >"$M/sym.out" 2>&1; rc=$?
[ $rc = 0 ] && [ -L "$M/app-sym/unraid-trivy-scan" ] && [ ! -e "$M/app-sym/unraid-cve-lens" ] && [ -f "$M/victim/keep" ] && grep -q 'symlink' "$M/sym.out" \
  && ok "migration: a symlinked old data folder is left alone" || bad "migration symlink guard: rc=$rc $(cat "$M/sym.out"); $(find "$M/app-sym")"
# array stopped: the appdata directory does not exist; nothing is created, the next run (array started) moves it
mig data "$M/not-mounted/appdata" >"$M/stopped.out" 2>&1; rc=$?
[ $rc = 0 ] && [ ! -e "$M/not-mounted" ] && ok "migration: appdata location missing (array stopped) is skipped and creates nothing" || bad "migration array stopped: rc=$rc $(cat "$M/stopped.out"); $(find "$M" -maxdepth 1)"
mkdir -p "$M/app-late"; mig data "$M/app-late" >/dev/null 2>&1; [ ! -e "$M/app-late/unraid-cve-lens" ] && ok "migration: nothing to move, nothing created" || bad "migration created a folder out of nothing"
mkdir -p "$M/app-late/unraid-trivy-scan"; echo late >"$M/app-late/unraid-trivy-scan/f"
mig data "$M/app-late" >/dev/null 2>&1; [ "$(cat "$M/app-late/unraid-cve-lens/f" 2>/dev/null)" = late ] && [ ! -e "$M/app-late/unraid-trivy-scan" ] \
  && ok "migration: retried later, the data folder is moved once the location exists" || bad "migration retry"
# the new folder already exists: both stay
mkdir -p "$M/app-both/unraid-trivy-scan" "$M/app-both/unraid-cve-lens"; echo o >"$M/app-both/unraid-trivy-scan/f"
mig data "$M/app-both" >/dev/null 2>&1; [ -f "$M/app-both/unraid-trivy-scan/f" ] && [ ! -e "$M/app-both/unraid-cve-lens/f" ] && ok "migration: never merges into an existing new data folder" || bad "migration both exist"
# a running old scan blocks the move
mkdir -p "$M/app-run/unraid-trivy-scan" "$M/oldrun"
printf '#!/bin/sh\nsleep 30\n' >"$M/trivy-scan"; chmod 755 "$M/trivy-scan"; "$M/trivy-scan" & TP=$!; echo $TP >"$M/oldrun/pid"
mig data "$M/app-run" >/dev/null 2>&1; [ -d "$M/app-run/unraid-trivy-scan" ] && [ ! -e "$M/app-run/unraid-cve-lens" ] && ok "migration: not moved while an old scan is running" || bad "migration moved under a running old scan"
kill $TP 2>/dev/null; rm -rf "$M/oldrun"
# the main script accepts the old label for cleanup (one release)
: >"$M/docker.log"; PATH="$M/bin2:$PATH" UTS_CFG=$M/none.cfg UTS_DATA=$M/appdata/unraid-cve-lens UTS_RUN=$M/run bash "$S" stop >/dev/null 2>&1
grep -q 'docker ps -aq --filter label=unraid-cve-lens=1' "$M/docker.log" && grep -q 'docker ps -aq --filter label=unraid-trivy-scan=1' "$M/docker.log" && grep -q 'docker rm -f abc123' "$M/docker.log" \
  && ok "cve-lens stop removes containers of the new and the old label" || bad "old-label cleanup in stop: $(cat "$M/docker.log")"
grep -q 'migrate-from-trivy-scan' <<<"$INST" && grep -q 'migrate-from-trivy-scan all' "$PLG" && ok ".plg post-install runs the migration (inline, every boot)" || bad ".plg does not run the migration"

# the transition file at the old path
BR=$HERE/unraid-trivy-scan.plg
BRI=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) { if ($f->getAttribute("Method")==="remove") continue; foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent; }' "$BR")
BRR=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) if ($f->getAttribute("Method")==="remove") foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent;' "$BR")
php -r '$d=new DOMDocument(); exit($d->load($argv[1], LIBXML_NOENT) ? 0 : 1);' "$BR" 2>/dev/null && ok "bridge: unraid-trivy-scan.plg is well-formed XML" || bad "bridge .plg does not parse"
BRV=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); $p=$d->documentElement; echo $p->getAttribute("name")," ",$p->getAttribute("version")," ",$p->getAttribute("pluginURL");' "$BR")
NEWURL=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); echo $d->documentElement->getAttribute("pluginURL");' "$PLG")
read -r bn bv bu <<<"$BRV"
[ "$bn" = unraid-trivy-scan ] && [ "$bu" = https://raw.githubusercontent.com/luuvasara/unraid-trivy-scan/main/unraid-trivy-scan.plg ] && [[ "$bv" > 2026.11.03 ]] \
  && ok "bridge: keeps the old name and pluginURL, version $bv sorts above the last real release 2026.11.03" || bad "bridge identity: $BRV"
grep -qF "plugin install $NEWURL" <<<"$BRI" && [[ $NEWURL == */unraid-cve-lens.plg ]] && ok "bridge: install runs 'plugin install <raw URL of unraid-cve-lens.plg>' ($NEWURL)" || bad "bridge install command: $BRI"
grep -q 'exit 1' <<<"$BRI" && grep -q 'ERROR' <<<"$BRI" && ok "bridge: aborts loudly when the new plugin cannot be installed" || bad "bridge has no failure exit"
grep -Eq "nohup setsid bash -c 'sleep [0-9]+; plugin remove unraid-trivy-scan.plg'" <<<"$BRI" && ok "bridge: old entry is removed by a detached, delayed job" || bad "bridge does not schedule the delayed remove"
! grep -q '<URL>' "$BR" && ok "bridge: no downloaded FILE (no package of its own)" || bad "bridge downloads a file"
! grep -Eq 'trivy-scan (uninstall|stop)|rm -rf[^\n]*(appdata|cve-lens)|unraid-cve-lens' <<<"$BRR" && grep -q 'removepkg' <<<"$BRR" && ok "bridge: remove block touches only old-plugin pieces, never the migrated data" || bad "bridge remove block: $BRR"
# the rename script is idempotent: in a copy of the tree (committed state plus new files), a second run changes nothing
RN=$W/rename-tree; rm -rf "$RN"; mkdir -p "$RN"
(cd "$HERE" && git ls-files -z --cached --others --exclude-standard | grep -zv '^packages/' | xargs -0 cp --parents -t "$RN" 2>/dev/null)
if (cd "$RN" && git init -q . && git add -A . && git -c user.name=t -c user.email=t@localhost commit -qm base && bash tools/rename-to-cve-lens.sh >/dev/null 2>&1 \
    && git add -A . && git -c user.name=t -c user.email=t@localhost commit -qm again --allow-empty && bash tools/rename-to-cve-lens.sh >/dev/null 2>&1 && [ -z "$(git status --porcelain)" ]); then
  ok "tools/rename-to-cve-lens.sh: re-running it on a renamed tree changes nothing"
else bad "rename script is not idempotent: $(cd "$RN" && git status --short | head -5)"; fi
# keep-old-end
exit $fail
