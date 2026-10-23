import json
import re
from pathlib import Path

import pytest

from security_scan import pins
from security_scan.errors import ScanError

ROOT = Path(__file__).resolve().parents[1]
PINS_TEXT = (ROOT / "scripts" / "pins.txt").read_text()
TOOLS = {"gitleaks", "opengrep", "osv-scanner", "trivy", "uv"}


def test_every_tool_has_one_pin_per_platform():
    loaded = pins.load(PINS_TEXT)

    assert {pin.name for pin in loaded} == TOOLS
    for name in TOOLS:
        platforms = [pin.platform for pin in loaded if pin.name == name]
        assert sorted(platforms) == sorted(pins.PLATFORMS)


def test_renovate_finds_every_pin_row_with_its_digest():
    config = json.loads((ROOT / "renovate.json").read_text())
    (manager,) = [
        m
        for m in config["customManagers"]
        if any(re.search(p.strip("/"), "scripts/pins.txt") for p in m["managerFilePatterns"])
    ]
    pattern = re.compile(manager["matchStrings"][0].replace("(?<", "(?P<"))

    found = {
        (m["depName"], m["packageName"], m["currentDigest"]) for m in pattern.finditer(PINS_TEXT)
    }

    assert found == {(p.name, p.repo, p.sha256) for p in pins.load(PINS_TEXT)}


def test_url_puts_the_version_into_the_asset_name():
    pin = pins.pin_for(pins.load(PINS_TEXT), "trivy", "linux-x86_64")

    assert pin.url("https://github.com") == (
        f"https://github.com/aquasecurity/trivy/releases/download/{pin.tag}/"
        f"trivy_{pin.version}_Linux-64bit.tar.gz"
    )
    assert pin.member == "trivy"


@pytest.mark.parametrize(
    ("system", "machine", "platform"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-aarch64"),
        ("Linux", "arm64", "linux-aarch64"),
        ("Darwin", "arm64", "darwin-arm64"),
    ],
)
def test_platform_names(system, machine, platform):
    assert pins.detect_platform(system, machine) == platform


def test_unsupported_platform_is_an_error():
    with pytest.raises(ScanError, match="unsupported platform: Darwin x86_64"):
        pins.detect_platform("Darwin", "x86_64")
