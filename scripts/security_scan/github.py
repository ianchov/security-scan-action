import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .report import MARKER

# The workflow token posts as this user. A marker comment by anyone else is never edited, so a
# planted comment cannot be overwritten or used to hide the findings.
BOT_LOGIN = "github-actions[bot]"
MAX_PAGES = 20
Urlopen = Callable[..., Any]


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PullRequest:
    api_url: str
    repository: str
    number: int


def pull_request_from_env(env: dict[str, str]) -> PullRequest | None:
    if env.get("GITHUB_EVENT_NAME") not in ("pull_request", "pull_request_target"):
        return None
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
    number = (event.get("pull_request") or {}).get("number")
    if not isinstance(number, int):
        return None
    api_url = env.get("GITHUB_API_URL") or "https://api.github.com"
    return PullRequest(api_url.rstrip("/"), env["GITHUB_REPOSITORY"], number)


def _call(
    method: str, url: str, token: str, urlopen: Urlopen, body: str | None = None
) -> tuple[Any, Any]:
    if not url.startswith(("https://", "http://")):
        raise GitHubError(f"refusing to call {url}")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        method=method,
        data=json.dumps({"body": body}).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "security-scan-action",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"null"), response.headers
    except urllib.error.HTTPError as error:
        raise GitHubError(f"GitHub {method} {url} returned {error.code}", error.code) from None
    except (urllib.error.URLError, OSError) as error:
        raise GitHubError(f"GitHub {method} {url} failed: {error}") from None


def _next_page(headers: Any) -> str | None:
    match = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link") or "")
    return match.group(1) if match else None


def _our_comment(pr: PullRequest, token: str, urlopen: Urlopen) -> dict | None:
    url: str | None = f"{pr.api_url}/repos/{pr.repository}/issues/{pr.number}/comments?per_page=100"
    for _ in range(MAX_PAGES):
        if url is None:
            return None
        comments, headers = _call("GET", url, token, urlopen)
        for item in comments:
            if (
                MARKER in (item.get("body") or "")
                and (item.get("user") or {}).get("login") == BOT_LOGIN
            ):
                return item
        url = _next_page(headers)
    return None


def publish(
    pr: PullRequest,
    token: str,
    body: str,
    has_findings: bool,
    urlopen: Urlopen = urllib.request.urlopen,
) -> str:
    existing = _our_comment(pr, token, urlopen)
    if existing is not None:
        url = f"{pr.api_url}/repos/{pr.repository}/issues/comments/{existing['id']}"
        _call("PATCH", url, token, urlopen, body)
        return "updated"
    if not has_findings:
        return "skipped"
    url = f"{pr.api_url}/repos/{pr.repository}/issues/{pr.number}/comments"
    _call("POST", url, token, urlopen, body)
    return "created"
