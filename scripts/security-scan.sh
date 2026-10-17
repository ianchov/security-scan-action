#!/usr/bin/env bash
# Install pinned, sha256-verified scanners and run them on the repository.
#   security-scan.sh
# Scans the whole repository: gitleaks reads the full git history, the other scanners every file.
# Exit status is non-zero when any scanner fails.
# Environment:
#   RULE_PACKS    opengrep-rules directories (globs allowed), space or newline separated
#   SCAN_EXCLUDE  extra paths for opengrep and trivy to skip, one per line
#   SECURITY_SCAN_CACHE  download cache (default: ~/.cache/security-scan)
# Renovate keeps each tool's release tag and asset sha256 current (see renovate.json). It takes
# a new digest from the release's checksum file, else from the downloaded asset.
set -euo pipefail
shopt -s inherit_errexit
# opengrep reads its UTF-8 rules with the locale's encoding; a bare container defaults to ASCII.
export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUTF8=1

cache="${SECURITY_SCAN_CACHE:-$HOME/.cache/security-scan}"
repo_root="$(git rev-parse --show-toplevel)"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-aarch64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  *) echo "unsupported platform: $(uname -sm)" >&2; exit 2 ;;
esac

# tool tag platform repo asset sha256 member(empty = plain binary)
# The asset is downloaded from https://github.com/<repo>/releases/download/<tag>/. In the asset
# name, {version} stands for the tag without its leading "v".
tools_table="
gitleaks v8.30.1 linux-x86_64 gitleaks/gitleaks gitleaks_{version}_linux_x64.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks
gitleaks v8.30.1 linux-aarch64 gitleaks/gitleaks gitleaks_{version}_linux_arm64.tar.gz e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 gitleaks
gitleaks v8.30.1 darwin-arm64 gitleaks/gitleaks gitleaks_{version}_darwin_arm64.tar.gz b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 gitleaks
opengrep v1.30.2 linux-x86_64 opengrep/opengrep opengrep_manylinux_x86 a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7
opengrep v1.30.2 linux-aarch64 opengrep/opengrep opengrep_manylinux_aarch64 90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8
opengrep v1.30.2 darwin-arm64 opengrep/opengrep opengrep_osx_arm64 f1aaa30b88959cb82522c4e1475816278a1f161f994509a518453c0455f9d24b
osv-scanner v2.7.0 linux-x86_64 google/osv-scanner osv-scanner_linux_amd64 160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
osv-scanner v2.7.0 linux-aarch64 google/osv-scanner osv-scanner_linux_arm64 4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7
osv-scanner v2.7.0 darwin-arm64 google/osv-scanner osv-scanner_darwin_arm64 d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b
trivy v0.76.0 linux-x86_64 aquasecurity/trivy trivy_{version}_Linux-64bit.tar.gz e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7 trivy
trivy v0.76.0 linux-aarch64 aquasecurity/trivy trivy_{version}_Linux-ARM64.tar.gz aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c trivy
trivy v0.76.0 darwin-arm64 aquasecurity/trivy trivy_{version}_macOS-ARM64.tar.gz e7ec0d21fe842553f59af99aba2efbcc822369fbaed27019c575408b6d135fce trivy
uv 0.13.1 linux-x86_64 astral-sh/uv uv-x86_64-unknown-linux-gnu.tar.gz eadd9d27c134ab5ac1ffd4473b97a741407f3ea238288f03121fc4deddf90220 uv-x86_64-unknown-linux-gnu/uv
uv 0.13.1 linux-aarch64 astral-sh/uv uv-aarch64-unknown-linux-gnu.tar.gz 9041c73c99fdc5892cf128140beb354eca9231d502068cc36e6cb53a8e59ad14 uv-aarch64-unknown-linux-gnu/uv
uv 0.13.1 darwin-arm64 astral-sh/uv uv-aarch64-apple-darwin.tar.gz cfe454573412ff7380d15fc7dae5997ab53ffce72fce0a78e91ddbc84001acd2 uv-aarch64-apple-darwin/uv
"
rules_commit=f1d2b562b414783763fd02a6ed2736eaed622efa
rules_sha256=9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d
# Secrets belong to gitleaks, Dockerfiles to trivy, so no generic/secrets or dockerfile packs.
# A pack may be a glob inside opengrep-rules, such as javascript/*/security.
rule_packs="${RULE_PACKS:-
python/lang/security python/django/security python/requests/security python/jwt/security
python/cryptography/security python/jinja2/security yaml/github-actions/security
yaml/docker-compose/security bash/*/security json/*/security javascript/*/security
go/*/security rust/*/security html/security
}"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# fetch URL SHA256 DEST: download to DEST unless a verified copy is already there.
fetch() {
  local url=$1 want=$2 dest=$3
  if [ -f "$dest" ] && [ "$(sha256 "$dest")" = "$want" ]; then return; fi
  curl -fsSL --retry 3 -o "$dest.part" "$url"
  local got
  got="$(sha256 "$dest.part")"
  if [ "$got" != "$want" ]; then
    rm -f "$dest.part"
    echo "sha256 mismatch for $url: got $got, want $want" >&2
    exit 2
  fi
  mv "$dest.part" "$dest"
}

install_tool() {
  local name=$1 tag repo asset sum member version url dir
  read -r _ tag _ repo asset sum member < <(awk -v n="$name" -v p="$platform" '$1 == n && $3 == p' <<<"$tools_table")
  version="${tag#v}"
  url="https://github.com/$repo/releases/download/$tag/${asset//"{version}"/$version}"
  dir="$cache/$name-$version"
  mkdir -p "$dir"
  # Only the archive is hashed, so extract it on every run: a cached binary is never trusted.
  if [ -n "$member" ]; then
    fetch "$url" "$sum" "$dir/asset.tar.gz"
    tar -xzf "$dir/asset.tar.gz" -C "$dir" "$member"
  else
    fetch "$url" "$sum" "$dir/$name"
    chmod +x "$dir/$name"
  fi
  echo "| $name | $version | \`$sum\` | $url |" >>"$work/tools.md"
  echo "$dir/${member:-$name}"
}

# bandit from scripts/bandit-requirements.txt (hash-locked) into this run's temporary venv.
# uv picks the repository's Python (.python-version, else requires-python) and downloads it if
# missing, so bandit parses the code with the syntax the project uses. The install ignores the
# repository's uv config (--no-config), so a private index in pyproject.toml cannot break it.
install_bandit() {
  local uv venv="$work/bandit-venv"
  uv="$(install_tool uv)"
  export UV_CACHE_DIR="$cache/uv" UV_PYTHON_INSTALL_DIR="$cache/python"
  (cd "$repo_root" && "$uv" venv --quiet "$venv")
  "$uv" --no-config pip install --quiet --require-hashes --python "$venv/bin/python" \
    -r "$script_dir/bandit-requirements.txt"
  echo "$venv/bin/bandit"
}

# Extract into this run's temporary directory, so a stale or tampered tree is never used.
install_rules() {
  local archive="$cache/opengrep-rules-$rules_commit.tar.gz" dir="$work/opengrep-rules"
  fetch "https://codeload.github.com/opengrep/opengrep-rules/tar.gz/$rules_commit" "$rules_sha256" "$archive"
  mkdir -p "$dir"
  tar -xzf "$archive" -C "$dir" --strip-components=1
  echo "$dir"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Committed and uncommitted .py files, minus .gitignore'd ones: the files opengrep scans too.
mapfile -t python_files < <(git -C "$repo_root" ls-files --cached --others --exclude-standard '*.py')

gitleaks="$(install_tool gitleaks)"
opengrep="$(install_tool opengrep)"
osv="$(install_tool osv-scanner)"
trivy="$(install_tool trivy)"
rules="$(install_rules)"
bandit=""
[ ${#python_files[@]} -eq 0 ] || bandit="$(install_bandit)"

cd "$repo_root"
failed=()
results=()

run() {
  local label=$1
  shift
  echo "::group::$label"
  if "$@"; then
    echo "$label: passed"
    results+=("| $label | passed |")
  else
    echo "$label: FAILED"
    results+=("| $label | **FAILED** |")
    failed+=("$label")
  fi
  echo "::endgroup::"
}

run "gitleaks (secrets)" "$gitleaks" git --redact --no-banner --exit-code 1 .

# Test code is out of SAST scope: what it finds there is fixtures, not defects.
opengrep_args=(--exclude .venv --exclude tests --exclude tests.py --exclude 'test_*.py'
  --exclude '*_test.py' --exclude conftest.py)
trivy_args=(--skip-dirs .venv)
osv_args=()
excludes=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  excludes+=("${path%/}")
  opengrep_args+=(--exclude "$path")
  trivy_args+=(--skip-dirs "$path")
  osv_args+=(--experimental-exclude "${path%/}")
done <<<"${SCAN_EXCLUDE:-}"
# Split without globbing against the scanned repository, then glob inside the rules tree.
mapfile -t packs < <(tr -s ' \t' '\n' <<<"$rule_packs" | grep -v '^$')
for pack in "${packs[@]}"; do
  for dir in "$rules"/$pack; do
    [ -e "$dir" ] || { echo "opengrep rule pack not found: $pack" >&2; exit 2; }
    opengrep_args+=(--config "$dir")
  done
done
run "opengrep (SAST)" "$opengrep" scan --error --severity ERROR "${opengrep_args[@]}" .

# bandit: Python only, medium and high severity. Same files and test scope as opengrep.
# A [tool.bandit] table in pyproject.toml applies (skips, extra excludes).
bandit_scan() {
  local file prefix targets=() args=(-q -ll)
  for file in "${python_files[@]}"; do
    case "/$file" in
      */tests/* | */tests.py | */test_*.py | *_test.py | */conftest.py | /.venv/*) continue ;;
    esac
    for prefix in "${excludes[@]}"; do
      case "$file" in "$prefix"/* | "$prefix") continue 2 ;; esac
    done
    targets+=("$file")
  done
  [ ${#targets[@]} -gt 0 ] || { echo "No Python files in scope."; return 0; }
  grep -qs '^\[tool\.bandit\]' pyproject.toml && args+=(-c pyproject.toml)
  "$bandit" "${args[@]}" "${targets[@]}"
}
[ -z "$bandit" ] || run "bandit (Python SAST)" bandit_scan

# Lockfiles only (osv reads uv.lock, poetry.lock, requirements.txt, package-lock.json, ...);
# .gitignore'd paths are skipped. Any known vulnerability fails; ignore reviewed ones in
# osv-scanner.toml.
run "osv-scanner (dependencies)" "$osv" scan source --recursive --allow-no-lockfiles \
  "${osv_args[@]}" .

run "trivy config (IaC)" "$trivy" config --quiet --exit-code 1 --severity HIGH,CRITICAL \
  "${trivy_args[@]}" .

# What ran and with which pins, rules and scope: in the log, and in the job summary on Actions.
write_summary() {
  echo "## Security scan"
  echo
  echo "| Scanner | Result |"
  echo "|---|---|"
  printf '%s\n' "${results[@]}"
  echo
  echo "### Pinned tools ($platform)"
  echo
  echo "Each download runs only after its sha256 matches."
  echo
  echo "| Tool | Version | sha256 | Source |"
  echo "|---|---|---|---|"
  cat "$work/tools.md"
  echo
  echo "### opengrep rules"
  echo
  echo "[opengrep-rules@${rules_commit:0:12}](https://github.com/opengrep/opengrep-rules/tree/$rules_commit)" \
    "(archive sha256 \`$rules_sha256\`). Only ERROR-severity findings fail. Packs:"
  echo
  # shellcheck disable=SC2016 # literal Markdown backticks
  printf -- '- `%s`\n' "${packs[@]}"
  if [ -n "$bandit" ]; then
    echo
    echo "### bandit packages (hash-locked)"
    echo
    awk -F'==' '/^[A-Za-z0-9_.-]+==/ { split($2, v, /[ ;]/); printf "- %s %s\n", $1, v[1] }' \
      "$script_dir/bandit-requirements.txt"
  fi
  echo
  echo "### Scope"
  echo
  echo "- gitleaks: the full git history."
  echo "- opengrep, bandit: committed and uncommitted files, without .gitignore'd files, .venv and test files."
  echo "- osv-scanner: lockfiles, without .gitignore'd paths."
  echo "- trivy config: IaC files, without .venv."
  if [ ${#excludes[@]} -gt 0 ]; then
    # shellcheck disable=SC2016 # literal Markdown backticks
    echo "- Excluded by the exclude input: $(printf '`%s` ' "${excludes[@]}")"
  fi
}
write_summary >"$work/summary.md"
echo "::group::Scan summary"
cat "$work/summary.md"
echo "::endgroup::"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$work/summary.md" >>"$GITHUB_STEP_SUMMARY"

if [ ${#failed[@]} -gt 0 ]; then
  echo "Failed: ${failed[*]}" >&2
  exit 1
fi
echo "All scanners passed."
