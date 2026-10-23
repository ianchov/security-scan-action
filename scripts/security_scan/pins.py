from dataclasses import dataclass

from .errors import ScanError

PLATFORMS = ("linux-x86_64", "linux-aarch64", "darwin-arm64")
_PLATFORM_OF = {
    ("Linux", "x86_64"): "linux-x86_64",
    ("Linux", "aarch64"): "linux-aarch64",
    ("Linux", "arm64"): "linux-aarch64",
    ("Darwin", "arm64"): "darwin-arm64",
}
RULES_COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa"
RULES_SHA256 = "9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d"
RULES_URL = f"https://codeload.github.com/opengrep/opengrep-rules/tar.gz/{RULES_COMMIT}"


@dataclass(frozen=True)
class Pin:
    name: str
    tag: str
    platform: str
    repo: str
    asset: str
    sha256: str
    member: str

    @property
    def version(self) -> str:
        return self.tag.removeprefix("v")

    @property
    def filename(self) -> str:
        return self.asset.replace("{version}", self.version)

    def url(self, base: str) -> str:
        return f"{base}/{self.repo}/releases/download/{self.tag}/{self.filename}"


def load(text: str) -> list[Pin]:
    loaded = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) not in (6, 7):
            raise ScanError(f"pins.txt row has {len(fields)} fields, want 6 or 7: {line}")
        name, tag, platform, repo, asset, sha256 = fields[:6]
        member = fields[6] if len(fields) == 7 else ""
        loaded.append(Pin(name, tag, platform, repo, asset, sha256, member))
    return loaded


def pin_for(pins: list[Pin], name: str, platform: str) -> Pin:
    for pin in pins:
        if pin.name == name and pin.platform == platform:
            return pin
    raise ScanError(f"no pin for {name} on {platform}")


def detect_platform(system: str, machine: str) -> str:
    try:
        return _PLATFORM_OF[(system, machine)]
    except KeyError:
        raise ScanError(f"unsupported platform: {system} {machine}") from None
