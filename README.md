# security-scan-action

A composite action that runs open-source scanners on a repository and fails on findings.
No model, no account, no API key. To add it to a repository with one job, use the reusable
workflow in [ianchov/security-scan](https://github.com/ianchov/security-scan).

| Category | Scanner | Fails on |
|---|---|---|
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | any secret; on a pull request, only in commits after the base |
| SAST | [opengrep](https://github.com/opengrep/opengrep) 1.30.0 | ERROR-severity findings |
| Python SAST | [bandit](https://github.com/PyCQA/bandit) 1.9.4, only when the repository tracks `.py` files | MEDIUM and HIGH severity findings |
| Dependencies | [osv-scanner](https://github.com/google/osv-scanner) 2.6.0 | any known vulnerability in a lockfile; a repository without one passes |
| Dockerfile, IaC | [trivy](https://github.com/aquasecurity/trivy) `config` 0.74.0 | HIGH and CRITICAL misconfigurations |

All scanners always run; the job fails after the last one if any failed.

bandit catches what the opengrep ERROR gate lets through, such as `pickle.loads` and `eval`.
It runs from a temporary venv built with a pinned uv from `scripts/bandit-requirements.txt`,
which pins every package by hash. uv uses the repository's Python version (`.python-version` or
`requires-python`) and downloads it when the runner lacks it, so bandit parses the project's
syntax.

osv-scanner reads lockfiles only (`uv.lock`, `poetry.lock`, `requirements.txt`,
`package-lock.json`, ...), skips `.gitignore`d paths and the `exclude` input, and fails on any
severity. Ignore a reviewed advisory in `osv-scanner.toml`.

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
| `exclude` | empty | Extra paths for opengrep, bandit, osv-scanner and trivy to skip, one per line. `.venv` and test files (`tests/`, `tests.py`, `test_*.py`, `*_test.py`, `conftest.py`) are always skipped by opengrep and bandit. |

## Exceptions

Exceptions live in the scanned repository:

- `.gitleaksignore`: one gitleaks fingerprint per line, for a reviewed false positive. Rotate a
  real secret instead.
- `osv-scanner.toml`: `[[IgnoredVulns]]` entries with an `id` and a `reason`.
- `.trivyignore`: trivy check IDs.
- bandit: a `[tool.bandit]` table in `pyproject.toml` (`skips`, `exclude_dirs`), or a
  `# nosec B310` comment that names the check, with the reason beside it.

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
