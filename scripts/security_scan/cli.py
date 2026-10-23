import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from . import download, findings, github, pins, report, scope
from .errors import ScanError
from .report import ScanResult, Setup

SCRIPTS = Path(__file__).resolve().parent.parent
SCANNED_TOOLS = ("gitleaks", "opengrep", "osv-scanner", "trivy")


def _child_env(env: dict[str, str]) -> dict[str, str]:
    # opengrep reads its UTF-8 rules with the locale's encoding; a bare container defaults to ASCII.
    return {**env, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUTF8": "1"}


def _repo_root() -> Path:
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScanError(f"not inside a git repository: {error}") from None
    return Path(top.stdout.strip())


def _bandit_packages() -> list[str]:
    text = (SCRIPTS / "bandit-requirements.txt").read_text()
    return [
        f"{name} {version}"
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)", text, re.M)
    ]


def _install_bandit(uv: Path, cache: Path, work: Path, root: Path, env: dict[str, str]) -> Path:
    # uv picks the repository's Python (.python-version, else requires-python) and downloads it if
    # missing, so bandit parses the code with the syntax the project uses. --no-config keeps a
    # private index in the repository's pyproject.toml from breaking the install.
    uv_env = {
        **env,
        "UV_CACHE_DIR": str(cache / "uv"),
        "UV_PYTHON_INSTALL_DIR": str(cache / "python"),
    }
    venv = work / "bandit-venv"
    try:
        # uv is the sha256-verified pinned binary, run with an argument list and no shell.
        subprocess.run(  # noqa: S603 # nosemgrep
            [str(uv), "venv", "--quiet", str(venv)], cwd=root, env=uv_env, check=True
        )
        subprocess.run(  # noqa: S603 # nosemgrep
            [
                str(uv), "--no-config", "pip", "install", "--quiet", "--require-hashes",
                "--python", str(venv / "bin" / "python"),
                "-r", str(SCRIPTS / "bandit-requirements.txt"),
            ],
            env=uv_env,
            check=True,
        )  # fmt: skip
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScanError(f"bandit install failed: {error}") from None
    return venv / "bin" / "bandit"


def _run(label: str, argv: list[str], root: Path, env: dict[str, str]) -> bool:
    print(f"::group::{label}", flush=True)
    try:
        # argv starts with a sha256-verified pinned scanner; no shell.
        passed = subprocess.run(argv, cwd=root, env=env).returncode == 0  # noqa: S603 # nosemgrep
    except OSError as error:
        print(f"{label}: could not start: {error}", flush=True)
        passed = False
    print(f"{label}: {'passed' if passed else 'FAILED'}", flush=True)
    print("::endgroup::", flush=True)
    return passed


def _scanned(label, argv, report_path, parser, root, env, *parser_args) -> ScanResult:
    passed = _run(label, argv, root, env)
    found = [] if passed else findings.read(report_path, parser, *parser_args)
    return ScanResult(label, passed, found)


def _bandit_result(binary, files, excludes, commands, root, env) -> ScanResult:
    label = "bandit (Python SAST)"
    targets = scope.bandit_targets(files, excludes)
    if not targets:
        print(f"::group::{label}\nNo Python files in scope.\n{label}: passed\n::endgroup::")
        return ScanResult(label, True, [])
    config = re.search(r"^\[tool\.bandit\]", _read(root / "pyproject.toml"), re.M) is not None
    argv = commands.bandit(str(binary), targets, config)
    return _scanned(label, argv, commands.report("bandit"), findings.bandit, root, env)


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def _run_url(env: dict[str, str]) -> str:
    parts = [env.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")]
    return f"{parts[0]}/{parts[1]}/actions/runs/{parts[2]}" if all(parts) else ""


def _post_comment(results: list[ScanResult], env: dict[str, str]) -> None:
    if env.get("PR_COMMENT", "false").strip().lower() != "true":
        return
    try:
        pr = github.pull_request_from_env(env)
    except (OSError, ValueError, KeyError) as error:
        print(f"::warning::PR comment skipped: cannot read the event: {error}")
        return
    if pr is None:
        print("PR comment skipped: this run is not for a pull request.")
        return
    token = env.get("GITHUB_TOKEN", "")
    if not token:
        print("::warning::PR comment skipped: no GitHub token.")
        return
    body = report.comment(results, sha=env.get("GITHUB_SHA", ""), run_url=_run_url(env))
    has_findings = any(not result.passed for result in results)
    try:
        action = github.publish(pr, token, body, has_findings)
    except github.GitHubError as error:
        hint = ""
        if error.status in (401, 403, 404):
            hint = (
                " The token needs pull-requests: write; a pull request from a fork gets a "
                "read-only token."
            )
        print(f"::warning::PR comment not posted: {error}.{hint}")
        return
    print(f"PR comment {action}.")


def _scan(env: dict[str, str]) -> int:
    target = pins.detect_platform(platform.system(), platform.machine())
    pinned = pins.load((SCRIPTS / "pins.txt").read_text())
    root = _repo_root()
    cache = Path(env.get("SECURITY_SCAN_CACHE") or Path.home() / ".cache" / "security-scan")
    child_env = _child_env(env)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        used = [pins.pin_for(pinned, name, target) for name in SCANNED_TOOLS]
        binaries = {pin.name: str(download.install_tool(pin, cache)) for pin in used}
        rules = download.install_rules(pins.RULES_URL, pins.RULES_SHA256, cache, work)
        files = scope.python_files(root)
        bandit = None
        if files:
            uv_pin = pins.pin_for(pinned, "uv", target)
            used.append(uv_pin)
            bandit = _install_bandit(download.install_tool(uv_pin, cache), cache, work, root, env)
        excludes = scope.parse_excludes(env.get("SCAN_EXCLUDE", ""))
        packs = scope.parse_rule_packs(env.get("RULE_PACKS", ""))
        commands = scope.Commands(excludes, scope.expand_packs(rules, packs), work)

        results = [
            _scanned("gitleaks (secrets)", commands.gitleaks(binaries["gitleaks"]),
                     commands.report("gitleaks"), findings.gitleaks, root, child_env),
            _scanned("opengrep (SAST)", commands.opengrep(binaries["opengrep"]),
                     commands.report("opengrep"), findings.opengrep, root, child_env),
        ]  # fmt: skip
        if bandit is not None:
            results.append(_bandit_result(bandit, files, excludes, commands, root, child_env))
        results += [
            _scanned("osv-scanner (dependencies)", commands.osv(binaries["osv-scanner"]),
                     commands.report("osv"), findings.osv, root, child_env, root),
            _scanned("trivy config (IaC)", commands.trivy(binaries["trivy"]),
                     commands.report("trivy"), findings.trivy, root, child_env),
        ]  # fmt: skip

    setup = Setup(
        platform=target,
        tools=[(pin.name, pin.version, pin.sha256, pin.url(download.GITHUB)) for pin in used],
        rules_commit=pins.RULES_COMMIT,
        rules_sha256=pins.RULES_SHA256,
        packs=packs,
        bandit_packages=_bandit_packages() if bandit is not None else [],
        excludes=excludes,
    )
    failed = [result.label for result in results if not result.passed]
    details = report.findings_markdown(results, _run_url(env), report.COMMENT_LIMIT)
    page = report.summary(results, setup) + (f"\n## Findings\n{details}" if failed else "")
    if failed:
        print(f"::group::Findings\n{report.log_text(results)}\n::endgroup::")
    print(f"::group::Scan summary\n{page}::endgroup::")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a") as summary_file:
            summary_file.write(page)
    _post_comment(results, env)
    if failed:
        print(f"Failed: {' '.join(failed)}", file=sys.stderr)
        return 1
    print("All scanners passed.")
    return 0


def main(env: dict[str, str] | None = None) -> int:
    try:
        return _scan(dict(os.environ) if env is None else env)
    except ScanError as error:
        print(error, file=sys.stderr)
        return 2
