import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest

from security_scan import download
from security_scan.errors import ScanError
from security_scan.pins import Pin


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_gz(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def release_asset_base_url(tmp_path: Path, repo: str, tag: str, asset: str, data: bytes) -> str:
    path = tmp_path / "releases" / repo / "releases" / "download" / tag / asset
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    return (tmp_path / "releases").as_uri()


def test_fetch_verifies_then_reuses_the_verified_copy(tmp_path):
    source = tmp_path / "asset"
    source.write_bytes(b"tool")
    dest = tmp_path / "cache" / "asset"
    dest.parent.mkdir()

    download.fetch(source.as_uri(), sha(b"tool"), dest)
    source.unlink()
    download.fetch(source.as_uri(), sha(b"tool"), dest)

    assert dest.read_bytes() == b"tool"


def test_fetch_with_a_wrong_digest_keeps_nothing(tmp_path):
    source = tmp_path / "asset"
    source.write_bytes(b"tampered")
    dest = tmp_path / "asset.cached"

    with pytest.raises(ScanError, match="sha256 mismatch"):
        download.fetch(source.as_uri(), sha(b"tool"), dest)

    assert not dest.exists()
    assert not dest.with_name(dest.name + ".part").exists()


def test_fetch_replaces_a_changed_cached_file(tmp_path):
    source = tmp_path / "asset"
    source.write_bytes(b"tool")
    dest = tmp_path / "asset.cached"
    dest.write_bytes(b"changed in the cache")

    download.fetch(source.as_uri(), sha(b"tool"), dest)

    assert dest.read_bytes() == b"tool"


def test_install_tool_extracts_the_member_again_on_every_run(tmp_path):
    archive = tar_gz({"pkg/tool": b"#!/bin/sh\necho ok\n"})
    pin = Pin(
        "tool",
        "v1.2.3",
        "linux-x86_64",
        "o/tool",
        "tool_{version}.tar.gz",
        sha(archive),
        "pkg/tool",
    )
    base = release_asset_base_url(tmp_path, "o/tool", "v1.2.3", "tool_1.2.3.tar.gz", archive)
    cache = tmp_path / "cache"

    binary = download.install_tool(pin, cache, base)
    binary.write_text("changed")
    binary = download.install_tool(pin, cache, base)

    assert binary == cache / "tool-1.2.3" / "pkg" / "tool"
    assert binary.read_text() == "#!/bin/sh\necho ok\n"
    assert os.access(binary, os.X_OK)


def test_install_tool_makes_a_plain_binary_executable(tmp_path):
    pin = Pin("tool", "v2", "linux-x86_64", "o/tool", "tool-linux", sha(b"\x7fELF"), "")
    base = release_asset_base_url(tmp_path, "o/tool", "v2", "tool-linux", b"\x7fELF")

    binary = download.install_tool(pin, tmp_path / "cache", base)

    assert binary == tmp_path / "cache" / "tool-2" / "tool"
    assert os.access(binary, os.X_OK)


def test_install_rules_drops_the_top_directory(tmp_path):
    archive = tar_gz({"opengrep-rules-abc/python/lang/security/rule.yml": b"rules: []\n"})
    source = tmp_path / "rules.tar.gz"
    source.write_bytes(archive)

    rules = download.install_rules(
        source.as_uri(), sha(archive), tmp_path / "cache", tmp_path / "work"
    )

    assert (rules / "python" / "lang" / "security" / "rule.yml").read_text() == "rules: []\n"


def test_an_archive_member_outside_the_target_is_refused(tmp_path):
    archive = tar_gz({"../escaped": b"x"})
    pin = Pin("tool", "v1", "linux-x86_64", "o/tool", "tool.tar.gz", sha(archive), "../escaped")
    base = release_asset_base_url(tmp_path, "o/tool", "v1", "tool.tar.gz", archive)

    with pytest.raises(ScanError, match="unsafe archive member"):
        download.install_tool(pin, tmp_path / "cache", base)

    assert not (tmp_path / "cache" / "escaped").exists()
