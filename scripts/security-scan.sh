#!/usr/bin/env bash
# Install pinned, sha256-verified scanners and run them on the repository.
#   security-scan.sh [BASE_REF]
# BASE_REF limits gitleaks to the commits after it (a pull request's base). Without it,
# gitleaks scans the full history. Exit status is non-zero when any scanner fails.
# Environment:
#   RULE_PACKS    opengrep-rules directories, space or newline separated (default: Python set)
#   SCAN_EXCLUDE  extra paths for opengrep and trivy to skip, one per line
#   SECURITY_SCAN_CACHE  download cache (default: ~/.cache/security-scan)
# Renovate keeps each tool's release tag and asset sha256 current (see renovate.json). It takes
# a new digest from the release's checksum file, else from the downloaded asset.
set -euo pipefail
shopt -s inherit_errexit
# opengrep reads its UTF-8 rules with the locale's encoding; a bare container defaults to ASCII.
export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUTF8=1

base_ref="${1:-}"
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
opengrep v1.30.0 linux-x86_64 opengrep/opengrep opengrep_manylinux_x86 35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
opengrep v1.30.0 linux-aarch64 opengrep/opengrep opengrep_manylinux_aarch64 a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
opengrep v1.30.0 darwin-arm64 opengrep/opengrep opengrep_osx_arm64 0f5bc3dec09d995c61331a4017b856ede508f90d95b018d95f1dc6166be89fdd
osv-scanner v2.6.0 linux-x86_64 google/osv-scanner osv-scanner_linux_amd64 ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
osv-scanner v2.6.0 linux-aarch64 google/osv-scanner osv-scanner_linux_arm64 2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4
osv-scanner v2.6.0 darwin-arm64 google/osv-scanner osv-scanner_darwin_arm64 98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4
trivy v0.74.0 linux-x86_64 aquasecurity/trivy trivy_{version}_Linux-64bit.tar.gz 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a trivy
trivy v0.74.0 linux-aarch64 aquasecurity/trivy trivy_{version}_Linux-ARM64.tar.gz b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 trivy
trivy v0.74.0 darwin-arm64 aquasecurity/trivy trivy_{version}_macOS-ARM64.tar.gz 1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11 trivy
uv 0.13.0 linux-x86_64 astral-sh/uv uv-x86_64-unknown-linux-gnu.tar.gz 1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154 uv-x86_64-unknown-linux-gnu/uv
uv 0.13.0 linux-aarch64 astral-sh/uv uv-aarch64-unknown-linux-gnu.tar.gz 3ccfb6af6e242433eb552f7d9676abd5412c6595c497e990d9c8cb7b5bd4d2c3 uv-aarch64-unknown-linux-gnu/uv
uv 0.13.0 darwin-arm64 astral-sh/uv uv-aarch64-apple-darwin.tar.gz a9c1b29002cf3c83f07fa9cd8a887a3be0107d90e23189721221e7257db8e3d6 uv-aarch64-apple-darwin/uv
"
rules_commit=f1d2b562b414783763fd02a6ed2736eaed622efa
rules_sha256=9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d
# Secrets belong to gitleaks, Dockerfiles to trivy, so no generic/secrets or dockerfile packs.
rule_packs="${RULE_PACKS:-
python/lang/security python/django/security python/requests/security python/jwt/security
python/cryptography/security python/jinja2/security yaml/github-actions/security
yaml/docker-compose/security bash/lang/security
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
mapfile -t python_files < <(git -C "$repo_root" ls-files '*.py')

gitleaks="$(install_tool gitleaks)"
opengrep="$(install_tool opengrep)"
osv="$(install_tool osv-scanner)"
trivy="$(install_tool trivy)"
rules="$(install_rules)"
bandit=""
[ ${#python_files[@]} -eq 0 ] || bandit="$(install_bandit)"

cd "$repo_root"
failed=()

run() {
  local label=$1
  shift
  echo "::group::$label"
  if "$@"; then echo "$label: passed"; else echo "$label: FAILED"; failed+=("$label"); fi
  echo "::endgroup::"
}

gitleaks_args=(git --redact --no-banner --exit-code 1)
[ -n "$base_ref" ] && gitleaks_args+=(--log-opts "$base_ref..HEAD")
run "gitleaks (secrets)" "$gitleaks" "${gitleaks_args[@]}" .

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
for pack in $rule_packs; do opengrep_args+=(--config "$rules/$pack"); done
run "opengrep (SAST)" "$opengrep" scan --error --severity ERROR "${opengrep_args[@]}" .

# bandit: Python only, tracked files, medium and high severity. Same test scope as opengrep.
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

if [ ${#failed[@]} -gt 0 ]; then
  echo "Failed: ${failed[*]}" >&2
  exit 1
fi
echo "All scanners passed."
