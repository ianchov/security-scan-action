#!/usr/bin/env bash
# Print a release title (first line) and release notes (the rest) from the pinned versions that
# changed between two commits: scanners in scripts/pins.txt (scripts/security-scan.sh in older
# releases), packages in scripts/bandit-requirements.txt.
#   release-notes.sh TAG OLD_REF NEW_REF
set -euo pipefail
shopt -s inherit_errexit

tag=$1 old=$2 new=$3

# pins REF: "name version" per pinned tool or package at REF, sorted by name.
pins() {
  # A table row has a 64-hex sha256 column. Its position moved once, so search for it.
  { git show "$1:scripts/pins.txt" 2>/dev/null || git show "$1:scripts/security-scan.sh"; } | awk 'NF >= 5 { for (i = 4; i <= NF; i++)
    if (length($i) == 64 && $i ~ /^[0-9a-f]+$/) { sub(/^v/, "", $2); print $1, $2; next } }'
  git show "$1:scripts/bandit-requirements.txt" | awk -F'==' '/^[A-Za-z0-9_.-]+==/ {
    split($2, v, /[ ;]/); print tolower($1), v[1] }'
}

changes=$(join -a 1 -a 2 -e none -o 0,1.2,2.2 <(pins "$old" | sort -u) <(pins "$new" | sort -u) \
  | awk '$2 != $3')
if [ -z "$changes" ]; then
  echo "$tag"
  echo "No pinned version changed since $old."
  exit 0
fi

echo "$tag: $(awk '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $3 }' <<<"$changes")"
echo "Updates the pinned versions, each verified by its sha256:"
echo
awk '{
  if ($2 == "none") printf "- %s %s (added)\n", $1, $3
  else if ($3 == "none") printf "- %s %s (removed)\n", $1, $2
  else printf "- %s %s → %s\n", $1, $2, $3
}' <<<"$changes"
