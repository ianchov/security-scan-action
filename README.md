# security-scan-action

A composite action that runs four open-source scanners on a repository and fails on findings.
No model, no account, no API key. To add it to a repository with one job, use the reusable
workflow in [ianchov/security-scan](https://github.com/ianchov/security-scan).

| Category | Scanner | Fails on |
|---|---|---|
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | any secret; on a pull request, only in commits after the base |
| SAST | [opengrep](https://github.com/opengrep/opengrep) 1.30.0 | ERROR-severity findings |
| Dependencies | [osv-scanner](https://github.com/google/osv-scanner) 2.6.0 | any known vulnerability in a lockfile |
| Dockerfile, IaC | [trivy](https://github.com/aquasecurity/trivy) `config` 0.74.0 | HIGH and CRITICAL misconfigurations |

All four always run; the job fails after the last one if any failed.

## Usage

```yaml
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: ianchov/security-scan-action@v1
        with:
          exclude: |
            app/staticfiles
```

The action checks out the repository itself with full history (`fetch-depth: 0`) and without
persisted credentials.

| Input | Default | Meaning |
|---|---|---|
| `rule-packs` | Python set | [opengrep-rules](https://github.com/opengrep/opengrep-rules) directories, space or newline separated. The default: `python/{lang,django,requests,jwt,cryptography,jinja2}/security`, `yaml/github-actions/security`, `yaml/docker-compose/security`, `bash/lang/security`. |
| `exclude` | empty | Extra paths for opengrep and trivy to skip, one per line. `.venv` and test files (`tests/`, `tests.py`, `test_*.py`, `*_test.py`, `conftest.py`) are always skipped by opengrep. |

## Exceptions

Exceptions live in the scanned repository, never in inline comments:

- `.gitleaksignore`: one gitleaks fingerprint per line, for a reviewed false positive. Rotate a
  real secret instead.
- `osv-scanner.toml`: `[[IgnoredVulns]]` entries with an `id` and a `reason`.
- `.trivyignore`: trivy check IDs.

## Pinning

`scripts/security-scan.sh` holds each tool's version and the sha256 of each release asset for
Linux x86_64, Linux aarch64 and macOS arm64. Nothing runs before its digest matches. The digests
come from each tool's upstream checksum file. opengrep publishes none: its digests and the
opengrep-rules commit come from
[thyn-ai/security-toolchain](https://github.com/thyn-ai/security-toolchain)'s
`security/toolchain.lock`, which verified them with cosign.

Downloads are cached in `~/.cache/security-scan` (`SECURITY_SCAN_CACHE`). Only the downloaded
archives are cached; each run re-checks them and extracts them again, so a changed cached file is
never run.

## Run locally

```bash
bash scripts/security-scan.sh             # full history
bash scripts/security-scan.sh origin/main # commits after origin/main only
```

## Releases

Publish a `vX.Y.Z` release. `move-major-tag.yml` then points `v1` at it.
