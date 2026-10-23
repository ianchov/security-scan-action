import re
from dataclasses import dataclass, field

from .findings import Finding

MARKER = "<!-- security-scan-action -->"
COMMENT_LIMIT = 60_000


@dataclass(frozen=True)
class ScanResult:
    label: str
    passed: bool
    findings: list[Finding] | None


@dataclass(frozen=True)
class Setup:
    platform: str
    tools: list[tuple[str, str, str, str]]
    rules_commit: str
    rules_sha256: str
    packs: list[str]
    bandit_packages: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _text(value: str) -> str:
    # Scanner text comes from the scanned repository: no HTML, @-mentions or links.
    text = " ".join(str(value).split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"@(?=[\w-])", "@\u200b", text)
    return text.replace("](", "]\u200b(")


def _code(value: str) -> str:
    return "`" + " ".join(str(value).split()).replace("`", "'") + "`"


def _rule(finding: Finding) -> str:
    if finding.link.startswith("https://"):
        return f"[{_text(finding.rule)}]({finding.link.replace(')', '%29')})"
    return _code(finding.rule)


def _finding_block(number: int, finding: Finding) -> str:
    return (
        f"{number}. {_code(finding.location)}: {_rule(finding)}\n"
        f"   - Why: {_text(finding.why)}\n"
        f"   - Change: {_text(finding.fix)}\n"
    )


def _log_link(run_url: str) -> str:
    return f"[job log]({run_url})" if run_url else "job log"


def _blocks(results: list[ScanResult], run_url: str) -> list[tuple[str, bool]]:
    blocks = []
    for result in results:
        if result.passed:
            continue
        if result.findings is None:
            blocks.append(
                (
                    f"\n### {result.label}: failed without a readable report\n\n"
                    f"See the {_log_link(run_url)}.\n",
                    False,
                )
            )
            continue
        if not result.findings:
            blocks.append(
                (
                    f"\n### {result.label}: failed with no finding in its report\n\n"
                    f"See the {_log_link(run_url)}.\n",
                    False,
                )
            )
            continue
        count = _plural(len(result.findings), "finding")
        blocks.append((f"\n### {result.label}: {count}\n\n", False))
        blocks.extend(
            (_finding_block(number, finding), True)
            for number, finding in enumerate(result.findings, 1)
        )
    return blocks


def findings_markdown(results: list[ScanResult], run_url: str, limit: int) -> str:
    blocks = _blocks(results, run_url)
    out = ""
    for index, (block, _) in enumerate(blocks):
        remaining = sum(1 for _, is_finding in blocks[index:] if is_finding)
        footer = f"\n{remaining} more findings are in the {_log_link(run_url)}.\n"
        if len(out) + len(block) + len(footer) > limit:
            return out + footer
        out += block
    return out


def comment(results: list[ScanResult], sha: str, run_url: str, limit: int = COMMENT_LIMIT) -> str:
    failed = [result for result in results if not result.passed]
    short = sha[:7]
    if not failed:
        return f"{MARKER}\n## Security scan: all scanners passed at {short}\n\nNo findings.\n"
    total = sum(len(result.findings or []) for result in failed)
    head = (
        f"{MARKER}\n## Security scan: {_plural(len(failed), 'scanner')} failed, "
        f"{_plural(total, 'finding')} at {short}\n\n"
        "Each finding names the place, the reason and the change. "
        f"Full scanner output: {_log_link(run_url)}.\n"
    )
    return head + findings_markdown(results, run_url, limit - len(head))


def log_text(results: list[ScanResult]) -> str:
    lines = []
    for result in results:
        if result.passed:
            continue
        if not result.findings:
            lines.append(f"{result.label}: failed; its report lists no finding (see above)")
            continue
        lines.append(f"{result.label}: {_plural(len(result.findings), 'finding')}")
        for finding in result.findings:
            lines.append(f"  {finding.location}: {finding.rule}")
            lines.append(f"    Why: {finding.why}")
            lines.append(f"    Change: {finding.fix}")
            if finding.link:
                lines.append(f"    More: {finding.link}")
    return "\n".join(lines)


def summary(results: list[ScanResult], setup: Setup) -> str:
    out = ["## Security scan", "", "| Scanner | Result |", "|---|---|"]
    out += [f"| {r.label} | {'passed' if r.passed else '**FAILED**'} |" for r in results]
    out += [
        "",
        f"### Pinned tools ({setup.platform})",
        "",
        "Each download runs only after its sha256 matches.",
        "",
        "| Tool | Version | sha256 | Source |",
        "|---|---|---|---|",
    ]
    out += [
        f"| {name} | {version} | `{digest}` | {url} |" for name, version, digest, url in setup.tools
    ]
    out += [
        "",
        "### opengrep rules",
        "",
        f"[opengrep-rules@{setup.rules_commit[:12]}](https://github.com/opengrep/opengrep-rules/"
        f"tree/{setup.rules_commit}) (archive sha256 `{setup.rules_sha256}`). "
        "Only ERROR-severity findings fail. Packs:",
        "",
    ]
    out += [f"- `{pack}`" for pack in setup.packs]
    if setup.bandit_packages:
        out += ["", "### bandit packages (hash-locked)", ""]
        out += [f"- {package}" for package in setup.bandit_packages]
    out += [
        "",
        "### Scope",
        "",
        "- gitleaks: the full git history.",
        "- opengrep, bandit: committed and uncommitted files, without .gitignore'd files, .venv "
        "and test files.",
        "- osv-scanner: lockfiles, without .gitignore'd paths.",
        "- trivy config: IaC files, without .venv.",
    ]
    if setup.excludes:
        out.append("- Excluded by the exclude input: " + " ".join(f"`{p}`" for p in setup.excludes))
    return "\n".join(out) + "\n"
