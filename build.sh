#!/bin/bash
# build.sh [version] - build packages/unraid-cve-lens-<version>-x86_64-1.txz on a workstation (never on the server).
# The version defaults to the .plg's &version; (and must match it). The .plg's &md5; entity is updated from the
# built package and CHANGELOG.md is rebuilt from the .plg's <CHANGES>.
# Directory modes are forced (the build umask is not trusted) and the archive root is verified: a Slackware package
# extracts ./ over /, so a group-writable root entry would break the target system.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=unraid-cve-lens
PLG=$HERE/$NAME.plg
PLGVER=$(sed -n 's/^ *<!ENTITY version *"\([^"]*\)">.*/\1/p' "$PLG")
VER=${1:-$PLGVER}
[ "$VER" = "$PLGVER" ] || { echo "FATAL: version $VER != $NAME.plg &version; $PLGVER (bump the .plg first)"; exit 1; }
[[ $VER =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] || { echo "FATAL: version $VER is not YYYY.MM.DD[a-z]"; exit 1; }
OUT=$HERE/packages; mkdir -p "$OUT"
PKG=$OUT/$NAME-$VER-x86_64-1.txz
P=usr/local/emhttp/plugins/$NAME
ST=$(mktemp -d "$HERE/.build.XXXXXX"); trap 'rm -rf "$ST"' EXIT
chmod 755 "$ST"
# only what git tracks under src/: a merge or rename can leave empty or untracked directories in the work tree,
# and cp -a would ship them (an empty plugins/<old name>/ tree once did)
UNTRACKED=$(git -C "$HERE" ls-files --others --exclude-standard -- src)
[ -z "$UNTRACKED" ] || { echo "FATAL: untracked files under src/ (git add or remove them):"; echo "$UNTRACKED"; exit 1; }
(cd "$HERE/src" && git ls-files -z --cached -- . | xargs -0 cp -a --parents -t "$ST/")
find "$ST" -type d -exec chmod 755 {} +
find "$ST" -type f -exec chmod 644 {} +
chmod 755 "$ST/$P/scripts/cve-lens" "$ST/$P/scripts/migrate-from-trivy-scan" "$ST/$P/event/stopping_docker"   # emhttp_event runs only executable event files
bash -n "$ST/$P/event/stopping_docker"
bash -n "$ST/$P/scripts/cve-lens"
bash -n "$ST/$P/scripts/migrate-from-trivy-scan"
for f in "$ST/$P"/*.page "$ST/$P"/include/*.php; do
  LINT=$(php -d short_open_tag=1 -l "$f" 2>&1) || { echo "FATAL: php -l failed: $LINT"; exit 1; }
done
# packages/ holds the current build and the one before it: right after a release, raw.githubusercontent.com can serve
# the previous .plg for some minutes, and that .plg must still find its package. Older ones are removed.
KEEP=$(for f in "$OUT/$NAME"-*-x86_64-1.txz; do [ -e "$f" ] && [ "$f" != "$OUT/$NAME-$VER-x86_64-1.txz" ] && echo "$f"; done | sort -V | tail -n 1)
for f in "$OUT/$NAME"-*-x86_64-1.txz; do
  [ -e "$f" ] || continue
  [ "$f" = "$KEEP" ] || rm -f "$f" "$f.md5"
done
tar -C "$ST" --owner=root --group=root --numeric-owner --sort=name --mtime="$(tr . - <<<"${VER:0:10}") 00:00:00 UTC" -cJf "$PKG" .
ROOT=$(tar -tJvf "$PKG" | sed -n 1p)   # sed reads all input: head -1 + pipefail = SIGPIPE
echo "archive root entry: $ROOT"
case "$(awk '{print $1}' <<<"$ROOT")" in drwxr-xr-x) ;; *) echo "FATAL: archive root is not drwxr-xr-x"; rm -f "$PKG"; exit 1 ;; esac
tar -tJvf "$PKG" | awk '$1 ~ /^d/ && $1 != "drwxr-xr-x" {bad=1; print "FATAL dir mode: " $0} END{exit bad}'
tar -tJvf "$PKG" | awk '$2 != "0/0" {bad=1; print "FATAL owner: " $0} END{exit bad}'
(cd "$OUT" && md5sum "$(basename "$PKG")" >"$(basename "$PKG").md5")
MD5=$(cut -d' ' -f1 "$PKG.md5")
sed -i "s|^\( *<!ENTITY md5 *\)\"[^\"]*\">|\1\"$MD5\">|" "$PLG"
grep -q "<!ENTITY md5 *\"$MD5\">" "$PLG" || { echo "FATAL: could not write md5 into $PLG"; exit 1; }
python3 -c 'import sys,xml.dom.minidom as m; m.parse(sys.argv[1])' "$PLG" || { echo "FATAL: $PLG is not well-formed XML"; exit 1; }
{ echo "# Changelog"; echo
  echo "Copied by build.sh from the <CHANGES> block of $NAME.plg; edit the .plg, not this file."; echo
  sed -n '/^<CHANGES>/,/^<\/CHANGES>/p' "$PLG" | sed '1d;$d' | sed -e 's/^###/## /' -e 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g'
} >"$HERE/CHANGELOG.md"
echo "built $PKG"; cat "$PKG.md5"
