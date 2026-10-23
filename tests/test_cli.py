import json

import pytest

from security_scan import cli, github
from security_scan.findings import Finding
from security_scan.report import ScanResult

RESULTS = [
    ScanResult("trivy config (IaC)", False, [Finding("trivy", "Dockerfile", "DS-0002", "w", "f")])
]


@pytest.fixture
def env(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7}}))
    return {
        "PR_COMMENT": "true",
        "GITHUB_TOKEN": "tok",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_SHA": "a" * 40,
    }


@pytest.mark.parametrize(
    ("error", "names_the_permission"),
    [
        (github.GitHubError("GitHub POST url returned 403", status=403), True),
        (github.GitHubError("GitHub GET url returned 404", status=404), True),
        (github.GitHubError("GitHub POST url returned 401", status=401), True),
        (github.GitHubError("GitHub POST url returned 502", status=502), False),
        (github.GitHubError("GitHub GET url failed: Connection refused"), False),
    ],
    ids=["403", "404", "401", "502", "network"],
)
def test_a_failed_comment_only_warns_and_names_the_permission_for_a_refusal(
    env, monkeypatch, capsys, error, names_the_permission
):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(github, "publish", fail)

    cli._post_comment(RESULTS, env)

    out = capsys.readouterr().out
    assert out.startswith(f"::warning::PR comment not posted: {error}")
    assert ("pull-requests: write" in out) is names_the_permission
