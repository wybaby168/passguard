#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repository_root/checksums.sha256"
temporary_manifest=$(mktemp "${TMPDIR:-/tmp}/passguard-checksums.XXXXXX")
trap 'rm -f "$temporary_manifest"' EXIT

cd "$repository_root"
find . -type f \
  -not -path './.git/*' \
  -not -path './frontend/node_modules/*' \
  -not -path './frontend/dist/*' \
  -not -path './java/target/*' \
  -not -path '*/__pycache__/*' \
  -not -name '*.pyc' \
  -not -name '*.tgz' \
  -not -name 'checksums.sha256' \
  -print |
  LC_ALL=C sort |
  while IFS= read -r file; do
    shasum -a 256 "$file"
  done |
  sed 's#  \./#  #' >"$temporary_manifest"

mv "$temporary_manifest" "$manifest"
trap - EXIT
echo "Wrote $manifest"
