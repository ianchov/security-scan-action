import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    scanner: str
    location: str
    rule: str
    why: str
    fix: str
    link: str = ""


def read(path: Path, parser: Callable[..., list[Finding]], *args: Any) -> list[Finding] | None:
    try:
        data = json.loads(path.read_text())
        return parser(data, *args)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def _one_line(text: str | None) -> str:
    return " ".join(str(text or "").split())


def gitleaks(data: list[dict]) -> list[Finding]:
    # Only file, line, rule and fingerprint: never Secret, Match, Line or the author's email.
    found = []
    for item in data:
        commit = item.get("Commit") or ""
        location = f"{item['File']}:{item['StartLine']}"
        if commit:
            location += f" (commit {commit[:7]})"
        found.append(
            Finding(
                scanner="gitleaks",
                location=location,
                rule=item["RuleID"],
                why=_one_line(item.get("Description")),
                fix=(
                    "Remove the secret and rotate it: it stays readable in the git history. "
                    f"If it is not a secret, add `{item['Fingerprint']}` to .gitleaksignore."
                ),
            )
        )
    return found


_RULES_DIR = re.compile(r"^.*?opengrep-rules(?:-[0-9a-f]+)?\.")


def opengrep_rule(check_id: str) -> str:
    return _RULES_DIR.sub("", check_id, count=1)


def opengrep(data: dict) -> list[Finding]:
    found = []
    for result in data["results"]:
        extra = result.get("extra", {})
        rule = opengrep_rule(result["check_id"])
        references = extra.get("metadata", {}).get("references") or []
        if extra.get("fix"):
            fix = f"The rule's autofix replaces the matched code with `{_one_line(extra['fix'])}`."
        else:
            fix = (
                "Change the code as the rule says. If the line is reviewed and safe, "
                f"add a `nosemgrep: {rule}` comment with the reason."
            )
        found.append(
            Finding(
                scanner="opengrep",
                location=f"{result['path']}:{result['start']['line']}",
                rule=rule,
                why=_one_line(extra.get("message")),
                fix=fix,
                link=references[0] if references else "",
            )
        )
    return found


def bandit(data: dict) -> list[Finding]:
    found = []
    for result in data["results"]:
        cwe = (result.get("issue_cwe") or {}).get("id")
        why = (
            f"{_one_line(result['issue_text'])} Severity {result['issue_severity']}, "
            f"confidence {result['issue_confidence']}"
        )
        why += f", CWE-{cwe}." if cwe else "."
        found.append(
            Finding(
                scanner="bandit",
                location=f"{result['filename'].removeprefix('./')}:{result['line_number']}",
                rule=f"{result['test_id']} {result['test_name']}",
                why=why,
                fix=(
                    "Use the safe alternative from the linked page. If the code is reviewed and "
                    f"safe, add `# nosec {result['test_id']}` with the reason."
                ),
                link=result.get("more_info", ""),
            )
        )
    return found


MAX_ADVISORIES = 5


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def lowest_fix_above(current: str, fixed: list[str]) -> str | None:
    newer = [version for version in fixed if _version_key(version) > _version_key(current)]
    return min(newer, key=_version_key) if newer else None


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    return [
        event["fixed"]
        for affected in vuln.get("affected", [])
        if affected.get("package", {}).get("name", "").lower() == name.lower()
        for version_range in affected.get("ranges", [])
        if version_range.get("type") in ("ECOSYSTEM", "SEMVER")
        for event in version_range.get("events", [])
        if "fixed" in event
    ]


def _shorten(text: str, limit: int = 160) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + " …"


def _advisory(vuln: dict, severity: str | None) -> str:
    notes = [alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")][:1]
    if severity:
        notes.append(f"severity {severity}")
    label = vuln["id"] + (f" ({', '.join(notes)})" if notes else "")
    summary = _one_line(vuln.get("summary") or vuln.get("details", "").split(". ")[0])
    return f"{label}: {_shorten(summary)}" if summary else label


def _advisory_groups(package: dict) -> list[tuple[list[dict], str | None]]:
    """One entry per advisory: osv lists one advisory under several ids (PYSEC, GHSA)."""
    by_id = {vuln["id"]: vuln for vuln in package["vulnerabilities"]}
    seen: set[str] = set()
    groups = []
    for group in package.get("groups", []):
        members = [by_id[i] for i in group.get("ids", []) if i in by_id and i not in seen]
        if members:
            seen.update(vuln["id"] for vuln in members)
            groups.append((members, group.get("max_severity") or None))
    groups += [([vuln], None) for vuln in package["vulnerabilities"] if vuln["id"] not in seen]
    return groups


def _osv_package(package: dict, lockfile: str) -> Finding:
    name = package["package"]["name"]
    version = package["package"]["version"]
    groups = _advisory_groups(package)
    fixes = {
        members[0]["id"]: lowest_fix_above(
            version, [fixed for vuln in members for fixed in _fixed_versions(vuln, name)]
        )
        for members, _ in groups
    }
    known = [fix for fix in fixes.values() if fix]
    unfixed = [vuln_id for vuln_id, fix in fixes.items() if not fix]
    steps = []
    if known:
        steps.append(f"Update {name} to {max(known, key=_version_key)} or later in {lockfile}.")
    if unfixed:
        steps.append(
            f"No fixed version is published for {', '.join(unfixed)}: replace {name}, or record "
            "the reviewed risk as an [[IgnoredVulns]] entry with a reason in osv-scanner.toml."
        )
    count = len(groups)
    listed = [_advisory(members[0], severity) for members, severity in groups[:MAX_ADVISORIES]]
    if count > MAX_ADVISORIES:
        listed.append(f"and {count - MAX_ADVISORIES} more")
    return Finding(
        scanner="osv-scanner",
        location=lockfile,
        rule=f"{name} {version} ({package['package'].get('ecosystem', '?')})",
        why=(
            f"{name} {version} has {count} known vulnerabilit{'y' if count == 1 else 'ies'}: "
            + "; ".join(listed)
            + "."
        ),
        fix=" ".join(steps),
        link=f"https://osv.dev/vulnerability/{groups[0][0][0]['id']}",
    )


def osv(data: dict, root: Path) -> list[Finding]:
    found = []
    for result in data.get("results", []):
        source = Path(result["source"]["path"])
        try:
            lockfile = source.relative_to(root).as_posix()
        except ValueError:
            lockfile = source.as_posix()
        found.extend(_osv_package(package, lockfile) for package in result.get("packages", []))
    return found


def trivy(data: dict) -> list[Finding]:
    found = []
    for result in data.get("Results") or []:
        for misconfig in result.get("Misconfigurations") or []:
            if misconfig.get("Status", "FAIL") != "FAIL":
                continue
            line = (misconfig.get("CauseMetadata") or {}).get("StartLine")
            found.append(
                Finding(
                    scanner="trivy",
                    location=result["Target"] + (f":{line}" if line else ""),
                    rule=misconfig["ID"],
                    why=(
                        f"{misconfig['Title']} ({misconfig['Severity']}): "
                        f"{_one_line(misconfig.get('Message'))}"
                    ),
                    fix=_one_line(misconfig.get("Resolution")),
                    link=misconfig.get("PrimaryURL", ""),
                )
            )
    return found
