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
echo "docker \$*" | tr '\n' ' ' | sed 's/ $//' >>"$W/docker.log"; echo >>"$W/docker.log"
case "\$1" in ps) [ -f "$W/slow-ps" ] && sleep 20; [ -n "\${FAKE_PS:-}" ] && echo "\$FAKE_PS"; exit 0 ;; info) exit 0 ;; esac
case "\$1" in inspect) case " \$* " in
  *HostConfig.Privileged*) cat "$W/posture.out"; exit 0 ;;
  *" image "*) ;;
  *) [ -n "\${FAKE_PS:-}" ] && printf 'cid\\037sha256:%s\\037web:latest\\037/web\\037\\n' "\$FAKE_IMG"; exit 0 ;; esac ;; esac
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_JSON:-}" ] && [ -z "\${FAKE_OS_FAIL:-}" ] && { cat "\$FAKE_OS_JSON"; exit 0; } ;; esac   # a large Trivy result
case " \$* " in *" rootfs "*) [ -n "\${FAKE_OS_FAIL:-}" ] && { echo "FATAL fake failure" >&2; exit 1; }; echo '{"SchemaVersion":2,"Results":[]}' ;; esac
case " \$* " in *" db update "*)   # Grype DB download: with FAKE_GRYPE_DB=1, leave a DB in the directory mounted at /db
  [ -n "\${FAKE_GRYPE_DB:-}" ] && for a in "\$@"; do case "\$a" in *:/db) mkdir -p "\${a%:/db}/6" && echo x >"\${a%:/db}/6/vulnerability.db" ;; esac; done ;; esac
case " \$* " in *" --entrypoint sh "*)   # exploit data download: with FAKE_EXPLOIT=<dir>, leave the files in the directory mounted at /x
  d=; for a in "\$@"; do case "\$a" in *:/x) d="\${a%:/x}" ;; esac; done
  [ -n "\${FAKE_EXPLOIT:-}" ] && [ -n "\$d" ] && { cp "\$FAKE_EXPLOIT/kev.json" "\$d/kev.json.new"; cp "\$FAKE_EXPLOIT/epss.csv.gz" "\$d/epss.csv.gz.new"; }
  [ -n "\${FAKE_EXPLOIT_BAD:-}" ] && [ -n "\$d" ] && { echo "not json" >"\$d/kev.json.new"; echo "not gzip" >"\$d/epss.csv.gz.new"; }
  [ -n "\${FAKE_EXPLOIT_BIG:-}" ] && [ -n "\$d" ] && { cp "\$FAKE_EXPLOIT/kev.json" "\$d/kev.json.new"; truncate -s 52428801 "\$d/kev.json.new"; } ;; esac
case " \$* " in *" --download-db-only "*|*" --download-java-db-only "*)   # Trivy DB download: FAKE_DL=<bytes> writes that much
  # into the directory mounted at /tmp (as Trivy does under \$TMPDIR), waits FAKE_DL_WAIT s, snapshots the run state
  [ -n "\${FAKE_DB_FAIL:-}" ] && { echo "FATAL fake db failure" >&2; exit 1; }
  if [ -n "\${FAKE_DL:-}" ]; then
    for a in "\$@"; do case "\$a" in *:/tmp) mkdir -p "\${a%:/tmp}/trivy-1/oci-download-1" "\${a%:/tmp}/getter1"; truncate -s "\$FAKE_DL" "\${a%:/tmp}/trivy-1/oci-download-1/db.tar.gz" "\${a%:/tmp}/getter1/archive" ;; esac; done
    # FAKE_UNPACK=<bytes>: the unpacked database file Trivy writes into the cache after the download
    [ -n "\${FAKE_UNPACK:-}" ] && for a in "\$@"; do case "\$a" in *:/cache) mkdir -p "\${a%:/cache}/db"; truncate -s "\$FAKE_UNPACK" "\${a%:/cache}/db/trivy.db" ;; esac; done
    sleep "\${FAKE_DL_WAIT:-0}"
    cp "\$UTS_RUN/steps" "$W/snap-steps" 2>/dev/null; cp "\$UTS_RUN/dl" "$W/snap-dl" 2>/dev/null
  fi ;; esac
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
EXPLOIT_DATA=yes
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
  && ok "TRIVY_DB_KEEP=no, JAVA_DB_KEEP=no: scan works, both deleted when it ends" || bad "unkept Trivy DBs: $(find "$OSD/cache" -maxdepth 3)"
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
  && ok "OS_PKG_DB_KEEP=yes: DB downloaded into, kept in and mapped read-only from $OSD/grype" || bad "keep=yes: $(find "$OSD" -maxdepth 3 | head -20)"
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
# exploit data (CISA KEV, FIRST EPSS): the download is a "db" container with network, no Docker socket and only its own directory
XF=$HERE/tests/fixtures/exploit
FAKE_EXPLOIT=$XF osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
XL=$(grep -- '-exploit ' "$W/docker.log")
[ "$(grep -c . <<<"$XL")" = 1 ] && grep -q -- '--label unraid-cve-lens.role=db ' <<<"$XL" && grep -q -- '--cap-drop ALL --security-opt no-new-privileges' <<<"$XL" \
  && ! grep -q 'docker.sock\|--network\|--privileged\|--pid\|--mount' <<<"$XL" && [ "$(grep -o -- ' -v ' <<<"$XL" | wc -l)" = 1 ] \
  && grep -q -- "-v $OSD/exploit:/x " <<<"$XL" && grep -q -- '--read-only' <<<"$XL" && grep -qE -- 'aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64} ' <<<"$XL" \
  && grep -q 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' <<<"$XL" && grep -q 'https://epss.empiricalsecurity.com' <<<"$XL" \
  && ok "exploit data download: db role, network (default bridge), no Docker socket, only $OSD/exploit mounted, read-only, pinned Trivy image" || bad "exploit container: $XL"
[ -s "$OSD/exploit/kev.json" ] && [ -s "$OSD/exploit/epss.csv.gz" ] && [ ! -e "$OSD/exploit/kev.json.new" ] && [ ! -e "$OSD/exploit/epss.csv.gz.new" ] \
  && ok "exploit data: valid downloads kept in $OSD/exploit, no temporary files left" || bad "exploit files: $(ls -la "$OSD/exploit")"
cp "$OSD/exploit/kev.json" "$W/kev.good"
FAKE_EXPLOIT_BAD=1 osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
cmp -s "$OSD/exploit/kev.json" "$W/kev.good" && [ ! -e "$OSD/exploit/kev.json.new" ] && gzip -t "$OSD/exploit/epss.csv.gz" && grep -q 'keeping the previous copy' "$W/os.log" \
  && ok "exploit data: an invalid download is refused, the last good copy stays, with a warning" || bad "bad exploit download replaced the good copy: $(tail -3 "$W/os.log")"
FAKE_EXPLOIT=$XF FAKE_EXPLOIT_BIG=1 osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
cmp -s "$OSD/exploit/kev.json" "$W/kev.good" && [ ! -e "$OSD/exploit/kev.json.new" ] && ok "exploit data: a download over 50 MiB is refused, the last good copy stays" || bad "oversize exploit file accepted"
SZ=$(UTS_DATA=$OSD bash "$S" db-sizes)
grep -qE '^exploit_now=[0-9]+$' <<<"$SZ" && grep -qE '^exploit_last=[0-9]+$' <<<"$SZ" && ok "db-sizes reports the exploit data (now and last)" || bad "db-sizes exploit: $SZ"
: >"$W/docker.log"; printf '%s\n' 'OS_SCAN="no"' 'JAVA_DB="no"' >"$W/os.cfg"
FAKE_EXPLOIT=$XF UTS_CFG=$W/os.cfg UTS_DATA=$OSD UTS_RUN=$W/osrun UTS_LOG=$W/os.log UTS_PLUGIN_DIR=$P bash "$S" update-db --foreground
grep -q -- '-exploit ' "$W/docker.log" && ok "update-db refreshes the exploit data" || bad "update-db skipped exploit data"
osrun 'OS_SCAN="no"' 'JAVA_DB="no"' 'EXPLOIT_DATA="no"'
! grep -q -- '-exploit ' "$W/docker.log" && [ ! -e "$OSD/exploit" ] && ok "EXPLOIT_DATA=no: no download container, the kept files are removed" || bad "EXPLOIT_DATA=no: $(ls "$OSD"; grep exploit "$W/docker.log")"
mkdir -p "$W/victim3"; touch "$W/victim3/keep"; ln -s "$W/victim3" "$OSD/exploit"
FAKE_EXPLOIT=$XF osrun 'OS_SCAN="no"' 'JAVA_DB="no"'
[ -e "$W/victim3/keep" ] && [ ! -e "$W/victim3/kev.json" ] && ! grep -q -- '-exploit ' "$W/docker.log" && ok "a symlink in place of the exploit directory is not followed" || bad "followed an exploit symlink: $(ls "$W/victim3")"
rm -f "$OSD/exploit"
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
grep -Fq "[ ! -e /var/log/plugins/unraid-cve-lens.plg ]; then" <<<"$INST" && grep -Fq "nohup setsid bash -c 'sleep 15; /usr/local/sbin/update_cron' >/dev/null 2>&1 </dev/null &" <<<"$INST" \
  && ok "post-install re-reads the cron entry once the plugin is registered (detached, delayed)" || bad "post-install: no delayed update_cron"
grep -q 'cve-lens uninstall' <<<"$REM" && ok "remove block runs uninstall (stop, cron, optional cleanup)" || bad "remove block"
grep -q 'case $f in \*/unraid-cve-lens-2026[^)]*-x86_64-1.txz) ;;' <<<"$INST" && ok "old-package cleanup keeps the version being installed" || bad "package cleanup not version-preserving"
grep -q 'pluginURL="&pluginURL;"' "$PLG" && grep -q '<!ENTITY gitURL    "https://raw.githubusercontent.com/luuvasara/unraid-cve-lens/main">' "$PLG" \
  && grep -q '<!ENTITY pluginURL "&gitURL;/&name;.plg">' "$PLG" && ok "pluginURL = .../luuvasara/unraid-cve-lens/main/unraid-cve-lens.plg" || bad "pluginURL"
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

# ---------------------------------------------------------------- container risk: what the host script asks docker for
IMGID=$(printf 'e%.0s' $(seq 64))
python3 -I - "$W/posture.out" "$IMGID" <<'PY'
import json, sys
img = "sha256:" + sys.argv[2]
rows = [
  ["cid1", img, "/web", True, "host", "host", ["SYS_ADMIN"], [{"PathOnHost": "/dev/dri"}], "", "CMD", None, ["/var/run/docker.sock"], {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}, False, "web:latest"],
  ["cid2", img, "/quiet", False, "bridge", "", None, None, "1000:1000", None, ["/mnt/user/x:/x:rw"], [], {"22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "2222"}]}, False, "web@sha256:" + "a" * 64],
  ["cid3", img, "/ours", False, "bridge", "", None, None, "", None, None, [], {}, True, "aquasec/trivy"],
]
open(sys.argv[1], "w").write("\n".join(json.dumps(r) for r in rows) + "\n")
PY
FAKE_PS=cid FAKE_IMG=$IMGID osrun 'OS_SCAN="no"' 'JAVA_DB="no"' && ok "run with containers (fake docker) exits 0" || bad "posture run rc=$?: $(tail -3 "$W/os.log")"
PIN=$(grep 'HostConfig.Privileged' "$W/docker.log")
[ -n "$PIN" ] && ! grep -qE '\.Env|\.Cmd|\.Args|Entrypoint' <<<"$PIN" && ok "posture inspect names its fields and never asks for Env, Cmd, Entrypoint or the whole label set" || bad "posture inspect format: $PIN"
[ "$(osrep 'json_encode(array_column($r["posture"], "container"))')" = '["quiet","web"]' ] \
  && ok "report.posture: our own container left out, two containers listed" || bad "report posture: $(osrep 'json_encode($r["posture"])')"
[ "$(osrep 'json_encode([$r["posture"][1]["privileged"], $r["posture"][1]["socket"], $r["posture"][1]["ports"], $r["posture"][1]["latest"], $r["posture"][0]["ports"], $r["posture"][0]["latest"], $r["posture"][0]["image_idx"]], JSON_UNESCAPED_SLASHES)')" = '[true,true,["8080/tcp"],true,[],false,0]' ] \
  && ok "report.posture: flags and ports through the real script (loopback port and digest-pinned image not flagged)" || bad "posture flags: $(osrep 'json_encode($r["posture"])')"

# ---------------------------------------------------------------- run steps, download progress, log tail (progress panel)
# A real `run` with the fake docker: the steps file is planned from the settings, every step gets start/end/result,
# and the copy kept for the idle summary (last-steps) has no step left waiting or running. The fake Trivy DB download
# writes 5 MB under the /tmp mount and waits, so the sampler (every second here) must see it.
LS=$W/osdata/unraid-cve-lens/report/last-steps
stepf() { php -r 'require $argv[1]; $s = uts_steps($argv[2]); echo json_encode($s, JSON_UNESCAPED_SLASHES);' "$P/include/lib.php" "$1"; }
rm -f "$LS" "$W/snap-steps" "$W/snap-dl"
printf 'trivy=2000\n' >"$W/osdata/unraid-cve-lens/db-sizes" 2>/dev/null || { mkdir -p "$W/osdata/unraid-cve-lens"; printf 'trivy=2000\n' >"$W/osdata/unraid-cve-lens/db-sizes"; }
FAKE_DL=5000000 FAKE_UNPACK=700000 FAKE_DL_WAIT=3 UTS_DL_EVERY=1 osrun 'OS_SCAN="yes"' 'JAVA_DB="no"' 'REGISTRY_CHECK="yes"' && ok "run with steps and a fake 5 MB DB download exits 0" || bad "steps run rc=$?: $(tail -3 "$W/os.log")"
[ -f "$LS" ] && ok "last-steps written at the end of the run" || bad "no last-steps file"
J=$(stepf "$LS")
[ "$(php -r '$j=json_decode($argv[1],true); echo implode(" ", array_column($j["steps"], "id"));' "$J")" = "pull-trivy db-trivy pull-grype db-grype db-exploit scan os pkgmatch registry report" ] \
  && ok "steps planned in run order from the settings (no Java DB: no db-java step)" || bad "step ids: $J"
[ "$(php -r '$j=json_decode($argv[1],true); echo $j["mode"]," ",$j["result"]," ",count(array_filter($j["steps"], fn($s)=>in_array($s["state"],["waiting","running"])));' "$J")" = "scan ok 0" ] \
  && ok "last-steps: mode scan, result ok, no step left waiting or running" || bad "last-steps states: $J"
php -r '$j=json_decode($argv[1],true); foreach ($j["steps"] as $s) if ($s["state"]!=="skipped" && !($s["start"]>=$j["started"] && $s["end"]>=$s["start"] && $s["end"]<=$j["ended"])) exit(1); exit($j["ended"]>=$j["started"] && $j["started"]>0 ? 0 : 1);' "$J" \
  && ok "every step that ran has start <= end within the run's start and end" || bad "step times: $J"
[ "$(php -r '$j=json_decode($argv[1],true); $s=array_column($j["steps"], null, "id"); echo $s["pull-trivy"]["state"],"/",$s["pull-trivy"]["note"]," ",$s["db-trivy"]["state"]," ",$s["scan"]["state"],"/",$s["scan"]["note"]," ",$s["os"]["state"]," ",$s["pkgmatch"]["state"]," ",$s["db-exploit"]["state"]," ",$s["report"]["state"];' "$J")" \
   = "skipped/already present done skipped/no containers done failed failed done" ] \
  && ok "step results: image present skipped, DB done, no containers skipped, OS done, failed package match and exploit download recorded as failed" || bad "step results: $J"
[ "$(php -r '$j=json_decode($argv[1],true); $s=array_column($j["steps"], null, "id"); echo $s["db-trivy"]["bytes"];' "$J")" = 5000000 ] \
  && ok "db-trivy step keeps the bytes the download wrote (5000000)" || bad "db-trivy bytes: $J"
grep -q -- "-v $W/osdata/unraid-cve-lens/dl-tmp:/tmp .*--download-db-only" "$W/docker.log" && ok "Trivy DB container: TMPDIR (/tmp) on disk in the data directory, so the download can be measured" || bad "no dl-tmp mount: $(grep download-db-only "$W/docker.log")"
grep -- '--download-db-only' "$W/docker.log" | grep -q 'docker.sock' && bad "DB container got the Docker socket" || ok "DB container still has no Docker socket"
[ ! -e "$W/osdata/unraid-cve-lens/dl-tmp" ] && ok "dl-tmp removed after the download" || bad "dl-tmp left behind"
grep -q '^step2=db-trivy|running|' "$W/snap-steps" 2>/dev/null && grep -q '^step3=pull-grype|waiting|' "$W/snap-steps" \
  && ok "during the download: \$RUN/steps shows db-trivy running and the later steps waiting" || bad "steps during the run: $(cat "$W/snap-steps" 2>&1)"
grep -q '^step=db-trivy$' "$W/snap-dl" 2>/dev/null && grep -q '^bytes=5000000$' "$W/snap-dl" && grep -qE '^rate=[0-9]+$' "$W/snap-dl" \
  && ok "during the download: \$RUN/dl has the step, 5000000 bytes so far and a rate" || bad "download sample: $(cat "$W/snap-dl" 2>&1)"
grep -q '^unpacked=700000$' "$W/snap-dl" 2>/dev/null && grep -q '^expect=2048000$' "$W/snap-dl" && grep -qE '^urate=[0-9]+$' "$W/snap-dl" \
  && ok "during the download: the artifact is counted once (Trivy keeps a second copy), the unpacked trivy.db and the size expected from db-sizes are measured" || bad "unpack sample: $(cat "$W/snap-dl" 2>&1)"
[ ! -e "$W/osrun/steps" ] && [ ! -e "$W/osrun/dl" ] && ! compgen -G "$W/osrun/*.tmp.*" >/dev/null && ok "\$RUN/steps and \$RUN/dl removed when the run ends" || bad "run state left: $(ls "$W/osrun")"
pgrep -f "$S" >/dev/null && bad "a sampler process outlived the run" || ok "no sampler process left after the run"
# "stop" during a download: the sampler ends with the run (it used to keep writing $RUN/dl into the next run)
# (seen on a NAS-like VM: the run's cleanup sat in a slow `docker rm`; here the fake `docker rm` takes longer than
# stop waits, so the run is KILLed in the middle of its EXIT trap)
rm -f "$W/osrun/dl"; ( FAKE_DL=1000 FAKE_DL_WAIT=20 UTS_DL_EVERY=1 osrun 'OS_SCAN="no"' 'JAVA_DB="no"' >/dev/null 2>&1 & )
for _ in $(seq 1 50); do [ -f "$W/osrun/dl" ] && break; sleep 0.2; done
touch "$W/slow-ps"
UTS_STOP_WAIT=3 UTS_CFG=$W/os.cfg UTS_DATA=$W/osdata/unraid-cve-lens UTS_RUN=$W/osrun UTS_LOG=$W/os.log bash "$S" stop >/dev/null 2>&1
rm -f "$W/slow-ps"; sleep 3
if pgrep -f "$S" >/dev/null; then bad "a sampler outlived a stopped run: $(pgrep -af "$S")"; pkill -f "$S"; else ok "stop during a download: no sampler left"; fi
[ ! -e "$W/osrun/dl" ] && ok "stop during a download: \$RUN/dl is not written again" || bad "\$RUN/dl rewritten after stop: $(cat "$W/osrun/dl")"
# a failed run: no vulnerability DB. The failing step carries the reason, the steps after it are skipped, result failed
FD=$W/faildata/unraid-cve-lens; mkdir -p "$FD"
printf 'OS_SCAN="no"\nJAVA_DB="no"\nEXPLOIT_DATA="no"\n' >"$W/f.cfg"
FAKE_DB_FAIL=1 UTS_CFG=$W/f.cfg UTS_DATA=$FD UTS_RUN=$W/frun UTS_LOG=$W/f.log UTS_PLUGIN_DIR=$P UTS_NOTIFY=$W/none bash "$S" run; frc=$?
J=$(stepf "$FD/report/last-steps")
[ "$frc" = 1 ] && [ "$(php -r '$j=json_decode($argv[1],true); $s=array_column($j["steps"], null, "id"); echo $j["result"]," ",$s["db-trivy"]["state"],"/",$s["db-trivy"]["note"]," ",$s["scan"]["state"]," ",$s["report"]["state"];' "$J")" \
   = "failed failed/FATAL fake db failure skipped skipped" ] && grep -q '"note":"not run, the run failed before"' <<<"$J" \
  && ok "failed run: the failing step has the reason, later steps are skipped (not run), result failed" || bad "failed run steps (rc $frc): $J"
# update-db: only the database steps
FAKE_DB_FAIL='' UTS_CFG=$W/f.cfg UTS_DATA=$W/osdata/unraid-cve-lens UTS_RUN=$W/urun UTS_LOG=$W/u.log UTS_PLUGIN_DIR=$P bash "$S" update-db --foreground
J=$(stepf "$LS")
[ "$(php -r '$j=json_decode($argv[1],true); echo $j["mode"]," ",$j["result"]," ",implode(",", array_column($j["steps"], "id"));' "$J")" = "update-db ok pull-trivy,db-trivy" ] \
  && grep -q 'database update [0-9]*-[0-9]* started' "$W/u.log" && ok "update-db: steps are the image and the database only, result ok, start line in the log" || bad "update-db steps: $J"
# the PHP side: hostile steps/dl files, log tail sanitising and the run-id cut
HS=$W/hostile-steps; printf '%s\n' 'id=1-2' 'mode=scan' 'started=100' \
  'step1=db-trivy|running|100|0|0|0|99|<b>lab</b>|n|extra|fields' 'step2=EVIL|done|1|2|0|0|0|x|y' 'step3=scan|pwned|1|2|0|0|0|x|y' \
  'step4=scan|running|abc|2|3|9|0|Images'$'\x1b''[31m|ok' >"$HS"
J=$(stepf "$HS")
[ "$(php -r '$j=json_decode($argv[1],true); echo count($j["steps"])," ",$j["steps"][0]["label"]," ",$j["steps"][0]["note"]," ",$j["steps"][1]["start"]," ",$j["steps"][1]["label"];' "$J")" = "2 <b>lab</b> n|extra|fields 0 Images" ] \
  && ok "uts_steps: bad id and state dropped, numbers checked, escape codes removed, text left as data" || bad "uts_steps hostile: $J"
printf '%s\n' 'old line' '2026-11-04 10:00:00 scan 5-6 started (scope=running)' 'a'$'\x1b''[1mbold'$'\x07' 'b' >"$W/t.log"
T=$(UTS_LOG=$W/t.log php -r 'require $argv[1]; echo json_encode(uts_log_tail(10, 65536, "5-6"));' "$P/include/lib.php")
[ "$T" = '["2026-11-04 10:00:00 scan 5-6 started (scope=running)","abold","b"]' ] && ok "log tail: starts at this run's start line, escape codes and control characters removed" || bad "log tail: $T"
seq 1 700 | sed 's/^/line /' >"$W/t.log"
L=$(UTS_LOG=$W/t.log REQUEST_METHOD=GET php "$P/include/log.php")
[ "$(grep -c '^line ' <<<"$L")" = 500 ] && grep -q '^line 700$' <<<"$L" && ! grep -q '^line 200$' <<<"$L" && ok "log.php: the last 500 lines" || bad "log.php lines: $(grep -c '^line ' <<<"$L")"
grep -q '\$_GET\|\$_POST\|\$_REQUEST' "$P/include/log.php" && bad "log.php reads request parameters" || ok "log.php takes no request parameters (fixed file)"

# ---------------------------------------------------------------- aggregate on fixture Trivy JSON
php "$HERE/tests/aggregate-test.php" "$HERE" || fail=1
command -v node >/dev/null && { node "$HERE/tests/export-test.js" || fail=1; } || echo "FAIL node not found: CSV export test not run"
php "$HERE/tests/osinventory-test.php" "$HERE" || fail=1
php "$HERE/tests/ignore-test.php" "$HERE" || fail=1
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
    UTS_OLD_PLUGIN_DIR=$M/nonexistent UTS_UPDATE_CRON=$M/update_cron UTS_CVELENS=$S UTS_DATA=${2:-$M/appdata}/unraid-cve-lens \
    UTS_OLD_LOG=$M/log/unraid-trivy-scan.log UTS_LOG=$M/log/unraid-cve-lens.log UTS_BOOT_CONFIG=$M/bootcfg UTS_PLUGIN_STATE=$M/pstate \
    UTS_TMP_PLUGINS=$M/tmpplugins UTS_NOTIFY_DIR=$M/notify bash "$MIG" "${1:-all}"
}
# during the update the old plugin is still registered (the transition entry removes itself later)
mkdir -p "$M/log" "$M/bootcfg/plugins-removed" "$M/pstate" "$M/tmpplugins" "$M/notify/unread" "$M/notify/archive"
: >"$M/pstate/unraid-trivy-scan.plg"
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
# idempotent: a run on it changes nothing, and never overwrites what the user changed since
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
# leftovers: old log, notifications, dashboard tile; once the old plugin is gone: flash folder, removed-plugin record
LF=$M/flash/unraid-trivy-scan
printf 'old line 1\nold line 2\n' >"$M/log/unraid-trivy-scan.log"; echo 'new line' >"$M/log/unraid-cve-lens.log"
printf 'event="Trivy scan"\nsubject="Trivy scan: 2 new"\nlink="/Settings/TrivyScan"\n' >"$M/notify/archive/Trivy_scan_1.notify"
printf 'event="Other"\nlink="/Settings/TrivyScan"\n' >"$M/notify/unread/Other_1.notify"
OH=$(printf '%s' 'Trivy image scan' | md5sum | cut -d' ' -f1); NH=$(printf '%s' 'CVE Lens' | md5sum | cut -d' ' -f1)
printf '{"db_box3":"aaa;%s;bbb","hidden_content":"%s"}' "$OH" "$OH" >"$M/bootcfg/dashboard_settings.json"
echo plg >"$M/bootcfg/plugins-removed/unraid-trivy-scan.plg"; echo plg >"$M/tmpplugins/unraid-trivy-scan.plg"
echo 'custom' >"$LF/notes.txt"
mig all >"$M/left1.out" 2>&1
[ ! -e "$M/log/unraid-trivy-scan.log" ] && grep -q '^new line$' "$M/log/unraid-cve-lens.log" && grep -q '^old line 2$' "$M/log/unraid-cve-lens.log" && grep -q 'former Trivy Scan' "$M/log/unraid-cve-lens.log" \
  && ok "leftovers: the old log is appended to the CVE Lens log and removed" || bad "leftovers log: $(cat "$M/left1.out")"
grep -qx 'link="/Settings/CveLens"' "$M/notify/archive/Trivy_scan_1.notify" && grep -qx 'link="/Settings/TrivyScan"' "$M/notify/unread/Other_1.notify" \
  && ok "leftovers: old notifications link to Settings, CVE Lens; other plugins' notifications untouched" || bad "leftovers notifications"
[ "$(cat "$M/bootcfg/dashboard_settings.json")" = "{\"db_box3\":\"aaa;$NH;bbb\",\"hidden_content\":\"$NH\"}" ] \
  && ok "leftovers: dashboard tile keeps its position and open/closed state under the new title" || bad "leftovers dashboard: $(cat "$M/bootcfg/dashboard_settings.json")"
[ -d "$LF" ] && [ -f "$M/bootcfg/plugins-removed/unraid-trivy-scan.plg" ] \
  && ok "leftovers: nothing of the old flash folder is removed while the old plugin is still installed" || bad "leftovers removed too early"
rm -f "$M/pstate/unraid-trivy-scan.plg"     # the transition entry has removed itself
mig all >"$M/left2.out" 2>&1
[ ! -e "$LF/unraid-trivy-scan.cfg" ] && [ ! -e "$LF/os-ignore.txt" ] && [ ! -e "$LF/cpe-map.txt" ] && [ ! -e "$LF/ignore.txt" ] && [ ! -e "$LF/unraid-trivy-scan.cron.migrated" ] \
  && [ -f "$LF/notes.txt" ] && grep -q 'kept: notes.txt' "$M/left2.out" && [ -f "$F/unraid-cve-lens.cfg" ] && [ -f "$F/os-ignore.txt" ] \
  && ok "leftovers: copied files leave the old flash folder (also the cfg the user changed in CVE Lens since: unchanged since copying); an unknown file stays and is named" \
  || bad "leftovers flash: $(cat "$M/left2.out"); $(ls -A "$LF" 2>&1)"
[ ! -e "$M/bootcfg/plugins-removed/unraid-trivy-scan.plg" ] && [ ! -e "$M/tmpplugins/unraid-trivy-scan.plg" ] \
  && ok "leftovers: Unraid's removed-plugin record and the downloaded old .plg are removed" || bad "leftovers plugin records"
echo changed >"$LF/os-ignore.txt"; mig all >"$M/left3.out" 2>&1
[ "$(cat "$LF/os-ignore.txt")" = changed ] && grep -q 'kept: .*os-ignore.txt' "$M/left3.out" && ok "leftovers: an old file changed after the migration is kept" || bad "leftovers changed file: $(cat "$M/left3.out")"
rm -f "$LF/notes.txt" "$LF/os-ignore.txt"; mig all >"$M/left4.out" 2>&1
[ ! -e "$LF" ] && grep -q 'old flash folder .* removed' "$M/left4.out" && ok "leftovers: the empty old flash folder is removed" || bad "leftovers rmdir: $(cat "$M/left4.out")"
# a marker from an earlier version (empty): files identical to the CVE Lens copy still go
mkdir -p "$M/m2/old" "$M/m2/new"; : >"$M/m2/new/.migrated-from-unraid-trivy-scan"; echo same >"$M/m2/old/cpe-map.txt"; echo same >"$M/m2/new/cpe-map.txt"
echo x >"$M/m2/old/unraid-trivy-scan.cfg"; echo y >"$M/m2/new/unraid-cve-lens.cfg"
UTS_OLD_FLASH=$M/m2/old UTS_NEW_FLASH=$M/m2/new UTS_OLD_RUN=$M/oldrun UTS_CVELENS=/bin/false UTS_OLD_LOG=$M/none UTS_LOG=$M/m2/log UTS_BOOT_CONFIG=$M/m2 \
  UTS_PLUGIN_STATE=$M/m2 UTS_TMP_PLUGINS=$M/m2 UTS_NOTIFY_DIR=$M/m2 UTS_UPDATE_CRON=/bin/true bash "$MIG" data >"$M/m2.out" 2>&1
[ ! -e "$M/m2/old/cpe-map.txt" ] && [ -f "$M/m2/old/unraid-trivy-scan.cfg" ] && ok "leftovers: with an older empty marker, identical copies go and different ones stay" || bad "leftovers old marker: $(cat "$M/m2.out")"
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
[ "$bn" = unraid-trivy-scan ] && [ "$bu" = https://raw.githubusercontent.com/luuvasara/unraid-cve-lens/main/unraid-trivy-scan.plg ] && [[ "$bv" > 2026.11.03 ]] \
  && ok "bridge: keeps the old plugin name and file name (renamed repository), version $bv sorts above the last real release 2026.11.03" || bad "bridge identity: $BRV"
grep -qF "plugin install $NEWURL" <<<"$BRI" && [[ $NEWURL == */unraid-cve-lens.plg ]] && ok "bridge: install runs 'plugin install <raw URL of unraid-cve-lens.plg>' ($NEWURL)" || bad "bridge install command: $BRI"
grep -q 'exit 1' <<<"$BRI" && grep -q 'ERROR' <<<"$BRI" && ok "bridge: aborts loudly when the new plugin cannot be installed" || bad "bridge has no failure exit"
grep -Eq "nohup setsid bash -c 'sleep [0-9]+; plugin remove unraid-trivy-scan.plg; /usr/local/emhttp/plugins/unraid-cve-lens/scripts/migrate-from-trivy-scan all " <<<"$BRI" \
  && ok "bridge: old entry is removed by a detached, delayed job, then the CVE Lens migration cleans up the leftovers" || bad "bridge does not schedule the delayed remove + cleanup"
! grep -q '<URL>' "$BR" && ok "bridge: no downloaded FILE (no package of its own)" || bad "bridge downloads a file"
! grep -Eq 'trivy-scan (uninstall|stop)|rm -rf[^\n]*(appdata|cve-lens)|unraid-cve-lens' <<<"$BRR" && grep -q 'removepkg' <<<"$BRR" && ok "bridge: remove block touches only old-plugin pieces, never the migrated data" || bad "bridge remove block: $BRR"
# the rename script is idempotent: in a copy of the tree (committed state plus new files), a run on it changes nothing
RN=$W/rename-tree; rm -rf "$RN"; mkdir -p "$RN"
(cd "$HERE" && git ls-files -z --cached --others --exclude-standard | grep -zv '^packages/' | xargs -0 cp --parents -t "$RN" 2>/dev/null)
if (cd "$RN" && git init -q . && git add -A . && git -c user.name=t -c user.email=t@localhost commit -qm base && bash tools/rename-to-cve-lens.sh >/dev/null 2>&1 && [ -z "$(git status --porcelain)" ]); then
  ok "tools/rename-to-cve-lens.sh: running it on the already renamed tree changes nothing"
else bad "rename script is not idempotent: $(cd "$RN" && git status --short | head -5)"; fi
# keep-old-end
exit $fail
