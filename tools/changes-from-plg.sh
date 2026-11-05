#!/bin/bash
# changes-from-plg.sh <file.plg> - print the <CHANGES> block as plain text: "###<version>" lines and "- item" lines.
# The one reader of that block: build.sh makes CHANGELOG.md and the package's include/changes.txt from this output.
set -euo pipefail
sed -n '/^<CHANGES>/,/^<\/CHANGES>/p' "$1" | sed '1d;$d' | sed -e 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g'
