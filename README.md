# security-scan-action

A composite action that runs open-source scanners on a repository and fails on findings.
No model, no account, no API key. To add it to a repository with one job, use the reusable
workflow in [ianchov/security-scan](https://github.com/ianchov/security-scan).

| Category | Scanner | Fails on |
|---|---|---|
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | any secret in the full git history, on pull requests too |
| SAST | [opengrep](https://github.com/opengrep/opengrep) 1.33.0 | ERROR-severity findings |
| Python SAST | [bandit](https://github.com/PyCQA/bandit) 1.9.4, only when the repository has `.py` files | MEDIUM and HIGH severity findings |
| Dependencies | [osv-scanner](https://github.com/google/osv-scanner) 2.7.0 | any known vulnerability in a lockfile; a repository without one passes |
| Dockerfile, IaC | [trivy](https://github.com/aquasecurity/trivy) `config` 0.76.1 | HIGH and CRITICAL misconfigurations |

All scanners always run; the job fails after the last one if any failed.

Each run writes a summary to the log and to the job summary page: the result of each scanner, the
version, sha256 and source of each tool, the opengrep-rules commit and packs, the bandit packages,
and what each scanner skips. Reviewers see what ran without opening this repository.

When a scanner fails, the log and the job summary list each finding: where it is (file and line,
or the lockfile), the rule, why it matters, and what to change. For a vulnerable dependency, the
change names the lowest version that fixes every known advisory. With `pr-comment: true`, the same
list goes into one pull request comment, which later runs update. A secret is never shown: gitleaks
runs with `--redact`, and only its file, line, rule and fingerprint are reported.

bandit catches what the opengrep ERROR gate lets through, such as `pickle.loads` and `eval`.
It runs from a temporary venv built with a pinned uv from `scripts/bandit-requirements.txt`,
which pins every package by hash. uv uses the repository's Python version (`.python-version`,
else `requires-python`) and downloads it when the runner lacks it, so bandit parses the
project's syntax. The install ignores the repository's uv settings, such as a private index.

opengrep and bandit scan committed and uncommitted files, but not `.gitignore`d ones.

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
  pull-requests: write # only for pr-comment

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: ianchov/security-scan-action@v1
        with:
          pr-comment: true
          exclude: |
            app/staticfiles
```

The action checks out the repository itself with full history (`fetch-depth: 0`) and without
persisted credentials. It needs `python3` 3.10 or later on the runner (GitHub's Ubuntu images
have it) and no Python packages.

| Input | Default | Meaning |
|---|---|---|
| `rule-packs` | default set | [opengrep-rules](https://github.com/opengrep/opengrep-rules) directories, space or newline separated. Globs such as `javascript/*/security` work. The default: `python/{lang,django,requests,jwt,cryptography,jinja2}/security`, `yaml/github-actions/security`, `yaml/docker-compose/security`, `bash/*/security`, `json/*/security`, `javascript/*/security`, `go/*/security`, `rust/*/security`, `html/security`. |
| `exclude` | empty | Extra paths for opengrep, bandit, osv-scanner and trivy to skip, one per line. `.venv` and test files (`tests/`, `tests.py`, `test_*.py`, `*_test.py`, `conftest.py`) are always skipped by opengrep and bandit. |
| `pr-comment` | `false` | `true` posts the findings as one pull request comment and updates it on later runs. A clean scan only updates an earlier comment. Needs `pull-requests: write`. On a pull request from a fork the workflow token cannot comment: the run logs a warning and the scan result does not change. |
| `github-token` | the workflow token | Token for the pull request comment. |

## Exceptions

Exceptions live in the scanned repository:

- `.gitleaksignore`: one gitleaks fingerprint per line, for a reviewed false positive. Rotate a
  real secret instead.
- `osv-scanner.toml`: `[[IgnoredVulns]]` entries with an `id` and a `reason`.
- `.trivyignore`: trivy check IDs.
- bandit: a `[tool.bandit]` table in `pyproject.toml` (`skips`, `exclude_dirs`), or a
  `# nosec B310` comment that names the check, with the reason beside it.

## Pinning

`scripts/pins.txt` holds each tool's release tag and the sha256 of each release asset for
Linux x86_64, Linux aarch64 and macOS arm64. Nothing runs before its digest matches. The first
digests came from each tool's upstream checksum file. opengrep publishes none: its first digests
and the opengrep-rules commit came from
[thyn-ai/security-toolchain](https://github.com/thyn-ai/security-toolchain)'s
`security/toolchain.lock`, which verified them with cosign.

Renovate updates the tags and digests together. It takes each new digest from the release's
checksum file, else it downloads the asset and hashes it (opengrep). It also updates the packages
and hashes in `scripts/bandit-requirements.txt`. It waits 3 days after a release, then merges
minor and patch updates when `Self test` passes. `Self test` also scans a one-file Python
repository, so a bandit update that does not install fails. Major updates stay open for review.
Renovate does not update the opengrep-rules commit.

Downloads are cached in `~/.cache/security-scan` (`SECURITY_SCAN_CACHE`). Only the downloaded
archives are cached; each run re-checks them and extracts them again, so a changed cached file is
never run.

## Run locally

```bash
python3 scripts/security-scan.py
```

## Development

The action is a standard-library Python package in `scripts/security_scan/`. The tests need
[uv](https://docs.astral.sh/uv/):

```bash
uv run pytest -q                        # unit tests
SECURITY_SCAN_E2E=1 uv run pytest -q    # also a real scan of a repository with planted findings
uv run ruff check . && uv run ruff format --check .
```

## Releases

Publish a `vX.Y.Z` release. `move-major-tag.yml` then points `v1` at it.

When a Renovate pull request that changes `action.yml` or `scripts/` is merged (by Renovate or by
hand), `release.yml` publishes the next patch release and moves `v1`. Its title and notes list
the pinned versions that changed.
