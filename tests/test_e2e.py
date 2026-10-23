import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "security-scan.py"
TOKEN = "ghs_e2eWorkflowTokenNotForUse"
# Built at run time, so this file itself holds no token-shaped string.
FAKE_PAT = "ghp_" + "Zq8Lr2Nw4Tx6Vb1Mc3Kd5Pf7Hg9Js0Ay2Ue4W"

pytestmark = pytest.mark.skipif(
    os.environ.get("SECURITY_SCAN_E2E") != "1",
    reason="downloads the real scanners; set SECURITY_SCAN_E2E=1",
)


class GitHubApi(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.comments: list[dict] = []
        self.writes: list[tuple[str, str, str]] = []
        self.auth: set[str] = set()


class Handler(BaseHTTPRequestHandler):
    server: GitHubApi

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers["Content-Length"])))["body"]

    def do_GET(self):
        self.server.auth.add(self.headers["Authorization"])
        self._reply(200, self.server.comments)

    def do_POST(self):
        body = self._body()
        self.server.writes.append(("POST", self.path, body))
        comment = {"id": len(self.server.comments) + 1, "body": body}
        comment["user"] = {"login": "github-actions[bot]"}
        self.server.comments.append(comment)
        self._reply(201, comment)

    def do_PATCH(self):
        body = self._body()
        self.server.writes.append(("PATCH", self.path, body))
        comment_id = int(self.path.rsplit("/", 1)[1])
        self.server.comments[comment_id - 1]["body"] = body
        self._reply(200, self.server.comments[comment_id - 1])

    def log_message(self, *args):
        pass


@pytest.fixture
def api():
    server = GitHubApi()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
    )
    (repo / "settings.py").write_text(f'token = "{FAKE_PAT}"\n')
    (repo / "requirements.txt").write_text("requests==2.19.0\n")
    (repo / "Dockerfile").write_text("FROM ubuntu:24.04\nRUN echo hi\n")
    (repo / ".github" / "workflows" / "greet.yml").write_text(
        "on: issues\njobs:\n  greet:\n    runs-on: ubuntu-24.04\n    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "fixture")
    return repo


def scan(repo: Path, tmp_path: Path, api: GitHubApi) -> tuple[subprocess.CompletedProcess, str]:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7}}))
    summary = tmp_path / "summary.md"
    summary.write_text("")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "SECURITY_SCAN_CACHE": os.environ.get(
            "SECURITY_SCAN_CACHE", str(Path.home() / ".cache" / "security-scan")
        ),
        "PR_COMMENT": "true",
        "GITHUB_TOKEN": TOKEN,
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_API_URL": f"http://127.0.0.1:{api.server_address[1]}",
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "42",
        "GITHUB_SHA": "fb4f67264eea9c1ee339286fec0605dec0742c28",
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    result = subprocess.run(
        [sys.executable, str(ENTRY)], cwd=repo, env=env, capture_output=True, text=True, timeout=900
    )
    return result, summary.read_text()


def test_a_pull_request_with_findings_gets_one_comment_that_says_what_to_change(
    repo, tmp_path, api
):
    first, summary = scan(repo, tmp_path, api)
    second, _ = scan(repo, tmp_path, api)

    assert first.returncode == 1, first.stdout[-3000:] + first.stderr[-3000:]
    assert second.returncode == 1
    for label in ("gitleaks (secrets)", "opengrep (SAST)", "bandit (Python SAST)"):
        assert f"| {label} | **FAILED** |" in summary
    for label in ("osv-scanner (dependencies)", "trivy config (IaC)"):
        assert f"| {label} | **FAILED** |" in summary

    assert [(method, path) for method, path, _ in api.writes] == [
        ("POST", "/repos/o/r/issues/7/comments"),
        ("PATCH", "/repos/o/r/issues/comments/1"),
    ]
    (comment,) = api.comments
    body = comment["body"]
    for expected in (
        "`settings.py:1 (commit ",
        "github-pat",
        "`.github/workflows/greet.yml:6`",
        "run-shell-injection",
        "`app.py:5`",
        "B602 subprocess_popen_with_shell_equals_true",
        "Update requests to ",
        "`Dockerfile`",
        "DS-0002",
        "https://github.com/o/r/actions/runs/42",
    ):
        assert expected in body, expected
    assert "Why: " in body and "Change: " in body
    assert api.auth == {f"Bearer {TOKEN}"}
    for output in (body, summary, first.stdout, first.stderr):
        assert FAKE_PAT not in output
        assert TOKEN not in output
