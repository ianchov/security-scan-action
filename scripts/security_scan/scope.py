import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import ScanError

# Secrets belong to gitleaks, Dockerfiles to trivy, so no generic/secrets or dockerfile packs.
DEFAULT_RULE_PACKS = (
    "python/lang/security",
    "python/django/security",
    "python/requests/security",
    "python/jwt/security",
    "python/cryptography/security",
    "python/jinja2/security",
    "yaml/github-actions/security",
    "yaml/docker-compose/security",
    "bash/*/security",
    "json/*/security",
    "javascript/*/security",
    "go/*/security",
    "rust/*/security",
    "html/security",
)
# Test code is out of SAST scope: what it finds there is fixtures, not defects.
OPENGREP_SKIPS = (
    ".venv",
    "tests",
    "tests.py",
    "test_*.py",
    "*_test.py",
    "conftest.py",
)


def parse_excludes(text: str) -> list[str]:
    return [line.strip().rstrip("/") for line in text.splitlines() if line.strip()]


def parse_rule_packs(text: str) -> list[str]:
    return text.split() or list(DEFAULT_RULE_PACKS)


def expand_packs(rules: Path, packs: list[str]) -> list[Path]:
    dirs = []
    for pack in packs:
        pure = PurePosixPath(pack)
        matches = [] if pure.is_absolute() or ".." in pure.parts else sorted(rules.glob(pack))
        if not matches:
            raise ScanError(f"opengrep rule pack not found: {pack}")
        dirs.extend(matches)
    return dirs


def python_files(repo: Path) -> list[str]:
    """Committed and uncommitted .py files without .gitignore'd ones: what opengrep scans too."""
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],  # noqa: S607
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return listed.stdout.splitlines()


def _is_test_or_venv(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1]
    return (
        parts[0] == ".venv"
        or "tests" in parts[:-1]
        or name in ("tests.py", "conftest.py")
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def bandit_targets(files: list[str], excludes: list[str]) -> list[str]:
    return [
        path
        for path in files
        if not _is_test_or_venv(path)
        and not any(path == prefix or path.startswith(prefix + "/") for prefix in excludes)
    ]


@dataclass(frozen=True)
class Commands:
    excludes: list[str]
    rule_dirs: list[Path]
    reports: Path

    def report(self, name: str) -> Path:
        return self.reports / f"{name}.json"

    def _each(self, flag: str) -> list[str]:
        return [arg for path in self.excludes for arg in (flag, path)]

    def gitleaks(self, binary: str) -> list[str]:
        # --redact keeps the secret out of the log and out of the JSON report.
        return [
            binary, "git", "--redact", "--no-banner", "--exit-code", "1",
            "--report-format", "json", "--report-path", str(self.report("gitleaks")), ".",
        ]  # fmt: skip

    def opengrep(self, binary: str) -> list[str]:
        skips = [arg for path in OPENGREP_SKIPS for arg in ("--exclude", path)]
        configs = [arg for path in self.rule_dirs for arg in ("--config", str(path))]
        return [
            binary, "scan", "--error", "--severity", "ERROR", *skips, *self._each("--exclude"),
            *configs, f"--json-output={self.report('opengrep')}", ".",
        ]  # fmt: skip

    def bandit(self, binary: str, targets: list[str], config: bool) -> list[str]:
        settings = ["-c", "pyproject.toml"] if config else []
        return [
            binary, "-q", "-ll", *settings, "-f", "json", "-o", str(self.report("bandit")),
            *targets,
        ]  # fmt: skip

    def osv(self, binary: str) -> list[str]:
        return [
            binary, "scan", "source", "--recursive", "--allow-no-lockfiles",
            *self._each("--experimental-exclude"),
            "--format", "json", "--output-file", str(self.report("osv")), ".",
        ]  # fmt: skip

    def trivy(self, binary: str) -> list[str]:
        return [
            binary, "config", "--quiet", "--exit-code", "1", "--severity", "HIGH,CRITICAL",
            "--skip-dirs", ".venv", *self._each("--skip-dirs"),
            "--format", "json", "--output", str(self.report("trivy")), ".",
        ]  # fmt: skip
