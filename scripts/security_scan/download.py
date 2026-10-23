import hashlib
import shutil
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

from .errors import ScanError
from .pins import Pin

ATTEMPTS = 3
GITHUB = "https://github.com"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(url: str, want: str, dest: Path) -> None:
    if dest.is_file() and sha256_file(dest) == want:
        return
    part = dest.with_name(dest.name + ".part")
    _download(url, part)
    got = sha256_file(part)
    if got != want:
        part.unlink()
        raise ScanError(f"sha256 mismatch for {url}: got {got}, want {want}")
    part.replace(dest)


def _download(url: str, path: Path) -> None:
    if not url.startswith(("https://", "file://")):
        raise ScanError(f"refusing to download {url}: only https:// and file:// URLs")
    for attempt in range(1, ATTEMPTS + 1):
        try:
            # The scheme is checked above: https:// or file:// only.
            opened = urllib.request.urlopen(url, timeout=120)  # noqa: S310 # nosec B310
            with opened as response, path.open("wb") as out:
                shutil.copyfileobj(response, out)
            return
        except (urllib.error.URLError, OSError) as error:
            if attempt == ATTEMPTS:
                raise ScanError(f"download failed: {url}: {error}") from error
            time.sleep(2 * attempt)


def _safe_name(name: str, strip: int) -> PurePosixPath | None:
    parts = PurePosixPath(name).parts[strip:]
    if not parts:
        return None
    path = PurePosixPath(*parts)
    if path.is_absolute() or ".." in path.parts:
        raise ScanError(f"unsafe archive member: {name}")
    return path


def extract(archive: Path, target: Path, names: list[str] | None = None, strip: int = 0) -> None:
    """Extract regular files and directories; a member that would leave target is an error."""
    wanted = set(names or [])
    for name in wanted:
        _safe_name(name, strip)
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            if wanted and member.name not in wanted:
                continue
            path = _safe_name(member.name, strip)
            if path is None or not (member.isfile() or member.isdir()):
                continue
            member.name = str(path)
            members.append(member)
        missing = wanted - {str(_safe_name(m.name, 0)) for m in members}
        if missing:
            raise ScanError(f"{archive.name} has no member {', '.join(sorted(missing))}")
        for member in members:
            # The data filter also refuses links and device files (Python 3.12+, 3.10.12+).
            if hasattr(tarfile, "data_filter"):
                tar.extract(member, target, filter="data")
            else:
                tar.extract(member, target)  # noqa: S202 - names checked by _safe_name


def install_tool(pin: Pin, cache: Path, base: str = GITHUB) -> Path:
    """Verify the cached or downloaded asset, then extract the binary again: only the archive is
    hashed, so a cached binary is never trusted."""
    directory = cache / f"{pin.name}-{pin.version}"
    directory.mkdir(parents=True, exist_ok=True)
    if pin.member:
        archive = directory / "asset.tar.gz"
        fetch(pin.url(base), pin.sha256, archive)
        extract(archive, directory, names=[pin.member])
        binary = directory / pin.member
    else:
        binary = directory / pin.name
        fetch(pin.url(base), pin.sha256, binary)
    binary.chmod(binary.stat().st_mode | 0o111)
    return binary


def install_rules(url: str, sha256: str, cache: Path, work: Path) -> Path:
    """Extract into this run's work directory, so a stale or changed tree is never used."""
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"opengrep-rules-{sha256[:16]}.tar.gz"
    fetch(url, sha256, archive)
    rules = work / "opengrep-rules"
    rules.mkdir(parents=True)
    extract(archive, rules, strip=1)
    return rules
