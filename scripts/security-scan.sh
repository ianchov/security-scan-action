#!/usr/bin/env bash
# Install pinned, sha256-verified scanners and run them on the repository.
#   security-scan.sh [BASE_REF]
# BASE_REF limits gitleaks to the commits after it (a pull request's base). Without it,
# gitleaks scans the full history. Exit status is non-zero when any scanner fails.
# Environment:
#   RULE_PACKS    opengrep-rules directories, space or newline separated (default: Python set)
#   SCAN_EXCLUDE  extra paths for opengrep and trivy to skip, one per line
#   SECURITY_SCAN_CACHE  download cache (default: ~/.cache/security-scan)
# Versions and digests come from upstream checksum files (opengrep: thyn-ai/security-toolchain
# security/toolchain.lock, cosign-verified there). Bump a tool here and nowhere else.
set -euo pipefail
shopt -s inherit_errexit

base_ref="${1:-}"
cache="${SECURITY_SCAN_CACHE:-$HOME/.cache/security-scan}"
repo_root="$(git rev-parse --show-toplevel)"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-aarch64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  *) echo "unsupported platform: $(uname -sm)" >&2; exit 2 ;;
esac

# tool version platform url sha256 member(empty = plain binary)
tools_table="
gitleaks 8.30.1 linux-x86_64 https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks
gitleaks 8.30.1 linux-aarch64 https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 gitleaks
gitleaks 8.30.1 darwin-arm64 https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 gitleaks
opengrep 1.30.0 linux-x86_64 https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_x86 35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
opengrep 1.30.0 linux-aarch64 https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_aarch64 a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
opengrep 1.30.0 darwin-arm64 https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_osx_arm64 0f5bc3dec09d995c61331a4017b856ede508f90d95b018d95f1dc6166be89fdd
osv-scanner 2.6.0 linux-x86_64 https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64 ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
osv-scanner 2.6.0 linux-aarch64 https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_arm64 2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4
osv-scanner 2.6.0 darwin-arm64 https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_darwin_arm64 98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4
trivy 0.74.0 linux-x86_64 https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a trivy
trivy 0.74.0 linux-aarch64 https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 trivy
trivy 0.74.0 darwin-arm64 https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_macOS-ARM64.tar.gz 1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11 trivy
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
  local name=$1 version url sum member dir
  read -r _ version _ url sum member < <(awk -v n="$name" -v p="$platform" '$1 == n && $3 == p' <<<"$tools_table")
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
  echo "$dir/$name"
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

gitleaks="$(install_tool gitleaks)"
opengrep="$(install_tool opengrep)"
osv="$(install_tool osv-scanner)"
trivy="$(install_tool trivy)"
rules="$(install_rules)"

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
while IFS= read -r path; do
  [ -n "$path" ] || continue
  opengrep_args+=(--exclude "$path")
  trivy_args+=(--skip-dirs "$path")
done <<<"${SCAN_EXCLUDE:-}"
for pack in $rule_packs; do opengrep_args+=(--config "$rules/$pack"); done
run "opengrep (SAST)" "$opengrep" scan --error --severity ERROR "${opengrep_args[@]}" .

# osv-scanner exits 128 when the repository has no lockfile or manifest: nothing to check.
osv_scan() {
  local status=0
  "$osv" scan source --recursive . || status=$?
  [ "$status" -eq 128 ] && return 0
  return "$status"
}
run "osv-scanner (dependencies)" osv_scan

run "trivy config (IaC)" "$trivy" config --quiet --exit-code 1 --severity HIGH,CRITICAL \
  "${trivy_args[@]}" .

if [ ${#failed[@]} -gt 0 ]; then
  echo "Failed: ${failed[*]}" >&2
  exit 1
fi
echo "All scanners passed."
