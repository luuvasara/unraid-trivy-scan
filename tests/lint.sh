#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# lint.sh - shellcheck (koalaman/shellcheck:stable, run with --network none, repo mounted read-only) on every shell
# script and on the .plg's inline install/remove blocks (entities resolved, as Unraid runs them); php -l (with
# short_open_tag on, as on Unraid) on every page and PHP file; node --check on the page scripts; .plg well-formed.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-cve-lens
W=$HERE/tests/.work/lint; rm -rf "$W"; mkdir -p "$W"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }

n=0
while IFS= read -r -d '' blk; do
  n=$((n + 1)); printf '#!/bin/bash\n%s\n' "$blk" >"$W/plg-inline-$n.sh"
done < <(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("INLINE") as $i) echo $i->textContent, "\0";' "$HERE/unraid-cve-lens.plg")
[ "$n" -eq 3 ] && ok ".plg parses with entities resolved, 3 inline blocks" || bad ".plg inline blocks: $n"

FILES=(src/usr/local/emhttp/plugins/unraid-cve-lens/scripts/cve-lens src/usr/local/emhttp/plugins/unraid-cve-lens/scripts/migrate-from-trivy-scan src/usr/local/emhttp/plugins/unraid-cve-lens/event/stopping_docker tests/real-unraid-test.sh build.sh tests/lint.sh tests/unit.sh tests/e2e.sh tests/unraid-os.sh
       tests/run-tests.sh tests/render/render-test.sh tests/render/fetch-webgui.sh)
for f in "${FILES[@]}"; do [ -f "$HERE/$f" ] || bad "missing $f"; done
if docker image inspect koalaman/shellcheck:stable >/dev/null 2>&1; then
  if out=$(docker run --rm --network none -v "$HERE:/mnt:ro" -w /mnt koalaman/shellcheck:stable -x -S style "${FILES[@]}" \
           tests/.work/lint/plg-inline-*.sh 2>&1); then
    ok "shellcheck clean (style level): ${#FILES[@]} scripts + $n .plg blocks"
  else bad "shellcheck:"; echo "$out"; fi
else echo "skip shellcheck (image koalaman/shellcheck:stable not present locally)"; fi

for f in "$P"/*.page "$P"/include/*.php "$HERE"/tests/*.php "$HERE"/tests/render/*.php; do
  out=$(php -d short_open_tag=1 -l "$f" 2>&1) && ok "php -l ${f#"$HERE"/}" || bad "php -l $f: $out"
done
for f in "$P"/assets/*.js; do node --check "$f" && ok "node --check ${f#"$HERE"/}" || bad "node --check $f"; done
for f in "$P"/*.page; do
  php -r '[$h] = explode("\n---\n", file_get_contents($argv[1]), 2); exit(parse_ini_string($h) === false ? 1 : 0);' "$f" \
    && ok "page header parses: $(basename "$f")" || bad "page header $f"
done
exit $fail
