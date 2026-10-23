import json
from dataclasses import asdict
from pathlib import Path

import pytest

from security_scan import findings

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SENTINEL = "NOT-REDACTED-SENTINEL"


def fixture(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def test_gitleaks_names_the_place_rule_and_ignore_fingerprint():
    (pat, generic) = findings.gitleaks(fixture("gitleaks"))

    assert (pat.location, pat.rule) == ("settings.py:1 (commit fb4f672)", "github-pat")
    assert pat.why.startswith("Uncovered a GitHub Personal Access Token")
    assert "rotate" in pat.fix
    assert ".gitleaksignore" in pat.fix
    assert "fb4f67264eea9c1ee339286fec0605dec0742c28:settings.py:github-pat:1" in pat.fix
    assert generic.rule == "generic-api-key"


def test_gitleaks_never_carries_the_secret_or_the_author():
    rendered = json.dumps([asdict(f) for f in findings.gitleaks(fixture("gitleaks"))])

    assert SENTINEL not in rendered
    assert "dev@example.invalid" not in rendered


def test_opengrep_gives_the_rule_without_the_rules_path_and_its_reason():
    (injection, subprocess_audit, shell_true) = findings.opengrep(fixture("opengrep"))

    assert injection.location == ".github/workflows/greet.yml:6"
    assert injection.rule == "yaml.github-actions.security.run-shell-injection"
    assert injection.why.startswith("Using variable interpolation `${{...}}`")
    assert injection.link.startswith("https://docs.github.com/")
    assert subprocess_audit.rule == "python.lang.security.audit.dangerous-subprocess-use-audit"
    assert shell_true.location == "app.py:5"
    assert shell_true.fix == "The rule's autofix replaces the matched code with `False`."


@pytest.mark.parametrize(
    "check_id",
    [
        "tmp.tmp.6MepYlYWB5.opengrep-rules.python.lang.security.audit.x",
        "tmp.opengrep-rules-f1d2b562b414.python.lang.security.audit.x",
        "python.lang.security.audit.x",
    ],
)
def test_opengrep_rule_id_drops_any_rules_directory(check_id):
    assert findings.opengrep_rule(check_id) == "python.lang.security.audit.x"


def test_bandit_gives_check_severity_and_docs():
    (shell, tmp) = findings.bandit(fixture("bandit"))

    assert (shell.location, shell.rule) == (
        "app.py:5",
        "B602 subprocess_popen_with_shell_equals_true",
    )
    assert shell.why == (
        "subprocess call with shell=True identified, security issue. "
        "Severity HIGH, confidence HIGH, CWE-78."
    )
    assert shell.link.startswith("https://bandit.readthedocs.io/")
    assert "# nosec B602" in shell.fix
    assert tmp.location == "app.py:9"


def test_osv_names_the_lowest_version_that_fixes_every_advisory():
    (requests,) = findings.osv(fixture("osv"), Path("/tmp/ssa-fixture"))

    assert requests.location == "requirements.txt"
    assert requests.rule == "requests 2.19.0 (PyPI)"
    assert "PYSEC-2018-28 (CVE-2018-18074, severity 7.5)" in requests.why
    assert "PYSEC-2023-74 (CVE-2023-32681, severity 6.1)" in requests.why
    assert requests.fix == "Update requests to 2.31.0 or later in requirements.txt."
    assert requests.link == "https://osv.dev/vulnerability/PYSEC-2018-28"


def test_osv_counts_an_advisory_listed_under_two_ids_once():
    report = fixture("osv")
    package = report["results"][0]["packages"][0]
    alias = dict(package["vulnerabilities"][0], id="GHSA-x84v-xcm2-53pg")
    package["vulnerabilities"].append(alias)

    (requests,) = findings.osv(report, Path("/tmp/ssa-fixture"))

    assert requests.why.startswith("requests 2.19.0 has 2 known vulnerabilities: ")
    assert "GHSA-x84v-xcm2-53pg" not in requests.why


def test_osv_lists_at_most_five_advisories():
    report = fixture("osv")
    package = report["results"][0]["packages"][0]
    first = package["vulnerabilities"][0]
    package["vulnerabilities"] = [dict(first, id=f"PYSEC-2099-{n}") for n in range(7)]
    package["groups"] = [{"ids": [f"PYSEC-2099-{n}"], "max_severity": "5.0"} for n in range(7)]

    (requests,) = findings.osv(report, Path("/tmp/ssa-fixture"))

    assert "has 7 known vulnerabilities" in requests.why
    assert "PYSEC-2099-4" in requests.why
    assert "PYSEC-2099-5" not in requests.why
    assert requests.why.endswith("and 2 more.")


def test_a_long_advisory_summary_is_cut_on_a_word_with_an_ellipsis():
    report = fixture("osv")
    vuln = report["results"][0]["packages"][0]["vulnerabilities"][0]
    vuln["summary"] = "word " * 60

    (requests,) = findings.osv(report, Path("/tmp/ssa-fixture"))

    assert "word word …" in requests.why
    assert "wor …" not in requests.why


def test_osv_without_a_published_fix_says_how_to_accept_the_risk():
    report = fixture("osv")
    for vuln in report["results"][0]["packages"][0]["vulnerabilities"]:
        vuln["affected"] = [{"package": vuln["affected"][0]["package"], "ranges": []}]

    (requests,) = findings.osv(report, Path("/tmp/ssa-fixture"))

    assert "No fixed version is published" in requests.fix
    assert "osv-scanner.toml" in requests.fix


@pytest.mark.parametrize(
    ("current", "fixed", "expected"),
    [
        ("1.8.0", ["1.10.0", "1.9.0"], "1.9.0"),
        ("2.19.0", ["2.3.0", "2.20.0"], "2.20.0"),
        ("1.0.0", ["0.9.0"], None),
    ],
)
def test_lowest_fix_above_the_current_version(current, fixed, expected):
    assert findings.lowest_fix_above(current, fixed) == expected


def test_trivy_gives_the_check_resolution_and_link():
    (root_user,) = findings.trivy(fixture("trivy"))

    assert (root_user.location, root_user.rule) == ("Dockerfile", "DS-0002")
    assert root_user.why == (
        "Image user should not be 'root' (HIGH): "
        "Specify at least 1 USER command in Dockerfile with non-root user as argument"
    )
    assert root_user.fix == "Add 'USER <non root user name>' line to the Dockerfile"
    assert root_user.link == "https://avd.aquasec.com/misconfig/ds-0002"


def test_a_missing_or_broken_report_reads_as_none(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")

    assert findings.read(tmp_path / "absent.json", findings.trivy) is None
    assert findings.read(broken, findings.trivy) is None
