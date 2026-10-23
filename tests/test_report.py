from security_scan import report
from security_scan.findings import Finding
from security_scan.report import ScanResult

SECRET_FINDING = Finding(
    scanner="gitleaks",
    location="settings.py:1 (commit fb4f672)",
    rule="github-pat",
    why="Uncovered a GitHub Personal Access Token.",
    fix="Remove it and rotate the token.",
)
TRIVY_FINDING = Finding(
    scanner="trivy",
    location="Dockerfile",
    rule="DS-0002",
    why="Image user should not be 'root' (HIGH): Specify a USER",
    fix="Add 'USER <non root user name>' line to the Dockerfile",
    link="https://avd.aquasec.com/misconfig/ds-0002",
)
RUN_URL = "https://github.com/o/r/actions/runs/1"


def test_comment_lists_each_failed_scanner_with_where_why_and_change():
    results = [
        ScanResult("gitleaks (secrets)", passed=False, findings=[SECRET_FINDING]),
        ScanResult("opengrep (SAST)", passed=True, findings=[]),
        ScanResult("trivy config (IaC)", passed=False, findings=[TRIVY_FINDING]),
    ]

    body = report.comment(results, sha="abc1234def", run_url=RUN_URL)

    assert body.startswith(report.MARKER)
    assert "## Security scan: 2 scanners failed, 2 findings at abc1234" in body
    assert "### gitleaks (secrets): 1 finding" in body
    assert "`settings.py:1 (commit fb4f672)`" in body
    assert "Why: Uncovered a GitHub Personal Access Token." in body
    assert "Change: Remove it and rotate the token." in body
    assert "### opengrep (SAST)" not in body
    assert "[DS-0002](https://avd.aquasec.com/misconfig/ds-0002)" in body
    assert f"[job log]({RUN_URL})" in body


def test_clean_comment_says_every_scanner_passed():
    results = [ScanResult("gitleaks (secrets)", passed=True, findings=[])]

    body = report.comment(results, sha="abc1234def", run_url=RUN_URL)

    assert body.startswith(report.MARKER)
    assert "## Security scan: all scanners passed at abc1234" in body


def test_a_failed_scanner_without_a_report_points_to_the_log():
    results = [ScanResult("osv-scanner (dependencies)", passed=False, findings=None)]

    body = report.comment(results, sha="abc1234def", run_url=RUN_URL)

    assert "### osv-scanner (dependencies): failed without a readable report" in body
    assert f"[job log]({RUN_URL})" in body


def test_scanner_text_cannot_mention_people_or_inject_html():
    hostile = Finding(
        scanner="opengrep",
        location="a.py:1",
        rule="rule",
        why="ping @admin <img src=x onerror=alert(1)> `x`",
        fix="see [here](javascript:alert(1))",
    )

    body = report.comment(
        [ScanResult("opengrep (SAST)", passed=False, findings=[hostile])],
        sha="a" * 40,
        run_url=RUN_URL,
    )

    assert "@admin" not in body
    assert "<img" not in body
    assert "](javascript:" not in body


def test_a_long_comment_is_cut_and_says_how_many_findings_are_left():
    many = [
        Finding("bandit", f"app.py:{n}", "B602", "shell=True. " * 20, "Use a list.")
        for n in range(500)
    ]

    body = report.comment(
        [ScanResult("bandit (Python SAST)", passed=False, findings=many)],
        sha="a" * 40,
        run_url=RUN_URL,
        limit=5000,
    )

    assert len(body) <= 5000
    assert "more findings are in the [job log]" in body
    assert "`app.py:0`" in body
    assert "`app.py:499`" not in body


def test_log_text_lists_findings_one_per_block():
    text = report.log_text(
        [ScanResult("trivy config (IaC)", passed=False, findings=[TRIVY_FINDING])]
    )

    assert text.splitlines()[:4] == [
        "trivy config (IaC): 1 finding",
        "  Dockerfile: DS-0002",
        "    Why: Image user should not be 'root' (HIGH): Specify a USER",
        "    Change: Add 'USER <non root user name>' line to the Dockerfile",
    ]
