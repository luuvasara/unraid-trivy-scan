#!/bin/bash
# fetch-webgui.sh - download Unraid's webGui stylesheets and fonts (github.com/unraid/webgui, pinned commit) into
# tests/.work/webgui for the render harness. They are not part of this repository.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
if [ "${1:-}" = 6.12 ]; then
  # webGui of Unraid 6.12.15 (tag 6.12.15): the stylesheets of that layout (default-<theme> + dynamix-<theme>, no
  # color palette) and DashStats.page, whose inline styles and tile markup the dashboard tile has to fit into
  COMMIT=140c88173f7aee634672dc83f8f776147240b2b2
  FILES="default-fonts.css default-cases.css font-awesome.css default-black.css default-white.css dynamix-black.css dynamix-white.css
         clear-sans.woff clear-sans-bold.woff clear-sans-italic.woff clear-sans-bold-italic.woff
         bitstream.woff bitstream-bold.woff font-awesome.woff font-cases.woff font-unraid.woff"
  ROOT=$HERE/tests/.work/webgui-6.12
else
  COMMIT=a91a4618a9de3284f6e057b21006f2cfd8468f4e   # unraid/webgui master on 2026-10-25
  FILES="default-fonts.css default-cases.css font-awesome.css default-color-palette.css default-base.css default-dynamix.css
         themes/black.css themes/white.css themes/gray.css themes/azure.css
         clear-sans.woff clear-sans-bold.woff clear-sans-italic.woff clear-sans-bold-italic.woff
         bitstream.woff bitstream-bold.woff font-awesome.woff font-cases.woff font-unraid.woff"
  ROOT=$HERE/tests/.work/webgui
fi
SRC=https://raw.githubusercontent.com/unraid/webgui/$COMMIT/emhttp/plugins/dynamix
D=$ROOT/webGui/styles
[ -f "$D/.commit" ] && [ "$(cat "$D/.commit")" = "$COMMIT" ] && exit 0
rm -rf "$D"; mkdir -p "$D/themes" "$ROOT/dynamix"
for f in $FILES; do
  curl -fsS --retry 2 -o "$D/$f" "$SRC/styles/$f"
done
curl -fsS --retry 2 -o "$ROOT/dynamix/DashStats.page" "$SRC/DashStats.page"
echo "$COMMIT" >"$D/.commit"
echo "webGui styles at $D"
