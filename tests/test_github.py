import io
import json
import urllib.error
from email.message import Message

import pytest

from security_scan import github
from security_scan.report import MARKER

API = "https://api.github.com"
PR = github.PullRequest(api_url=API, repository="o/r", number=7)
COMMENTS = f"{API}/repos/o/r/issues/7/comments?per_page=100"
BOT = {"login": "github-actions[bot]"}


class Response(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(json.dumps(body).encode())
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeApi:
    def __init__(self, pages=None, fail=None):
        self.pages = pages or {COMMENTS: ([], None)}
        self.fail = fail
        self.requests = []

    def __call__(self, request, timeout):
        body = json.loads(request.data) if request.data else None
        self.requests.append(
            (request.get_method(), request.full_url, request.get_header("Authorization"), body)
        )
        if self.fail and request.get_method() == self.fail:
            raise urllib.error.HTTPError(
                request.full_url, 403, "Forbidden", Message(), io.BytesIO(b"{}")
            )
        if request.get_method() == "GET":
            items, following = self.pages[request.full_url]
            headers = {"Link": f'<{following}>; rel="next"'} if following else {}
            return Response(items, headers)
        return Response({"id": 99})

    def writes(self):
        return [(m, url, b["body"]) for m, url, _, b in self.requests if m != "GET"]


def comment(id_, body, user=BOT):
    return {"id": id_, "body": body, "user": user}


def test_findings_without_a_comment_create_one():
    api = FakeApi()

    action = github.publish(PR, "tok", f"{MARKER}\nfindings", has_findings=True, urlopen=api)

    assert action == "created"
    assert api.writes() == [("POST", f"{API}/repos/o/r/issues/7/comments", f"{MARKER}\nfindings")]
    assert {auth for _, _, auth, _ in api.requests} == {"Bearer tok"}


def test_our_existing_comment_is_updated_not_duplicated():
    api = FakeApi({COMMENTS: ([comment(5, "hello"), comment(6, f"{MARKER}\nold")], None)})

    action = github.publish(PR, "tok", f"{MARKER}\nnew", has_findings=True, urlopen=api)

    assert action == "updated"
    assert api.writes() == [("PATCH", f"{API}/repos/o/r/issues/comments/6", f"{MARKER}\nnew")]


def test_a_marker_comment_by_someone_else_is_left_alone():
    planted = comment(6, f"{MARKER}\nplanted", user={"login": "mallory"})
    api = FakeApi({COMMENTS: ([planted], None)})

    action = github.publish(PR, "tok", f"{MARKER}\nnew", has_findings=True, urlopen=api)

    assert action == "created"
    assert [m for m, _, _ in api.writes()] == ["POST"]


def test_a_clean_scan_writes_nothing_when_no_comment_exists():
    api = FakeApi()

    assert (
        github.publish(PR, "tok", f"{MARKER}\nclean", has_findings=False, urlopen=api) == "skipped"
    )
    assert api.writes() == []


def test_a_clean_scan_updates_the_earlier_findings_comment():
    api = FakeApi({COMMENTS: ([comment(6, f"{MARKER}\nold findings")], None)})

    assert (
        github.publish(PR, "tok", f"{MARKER}\nclean", has_findings=False, urlopen=api) == "updated"
    )
    assert api.writes() == [("PATCH", f"{API}/repos/o/r/issues/comments/6", f"{MARKER}\nclean")]


def test_the_comment_is_found_on_a_later_page():
    page2 = f"{API}/repositories/1/issues/7/comments?per_page=100&page=2"
    api = FakeApi(
        {COMMENTS: ([comment(1, "a")], page2), page2: ([comment(2, f"{MARKER}\nold")], None)}
    )

    assert github.publish(PR, "tok", f"{MARKER}\nnew", has_findings=True, urlopen=api) == "updated"


def test_a_refused_write_raises_with_the_status():
    api = FakeApi(fail="POST")

    with pytest.raises(github.GitHubError, match="403") as refused:
        github.publish(PR, "tok", f"{MARKER}\nx", has_findings=True, urlopen=api)

    assert refused.value.status == 403


@pytest.mark.parametrize("event", ["pull_request", "pull_request_target"])
def test_pull_request_is_read_from_the_event(tmp_path, event):
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"pull_request": {"number": 7}}))
    env = {
        "GITHUB_EVENT_NAME": event,
        "GITHUB_EVENT_PATH": str(path),
        "GITHUB_API_URL": API,
        "GITHUB_REPOSITORY": "o/r",
    }

    assert github.pull_request_from_env(env) == PR


def test_a_push_has_no_pull_request(tmp_path):
    path = tmp_path / "event.json"
    path.write_text("{}")
    env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(path), "GITHUB_REPOSITORY": "o/r"}

    assert github.pull_request_from_env(env) is None
