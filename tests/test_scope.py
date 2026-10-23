import pytest

from security_scan import scope
from security_scan.errors import ScanError


def test_excludes_drop_blank_lines_spaces_and_trailing_slashes():
    assert scope.parse_excludes("app/static/\n\n  vendor  \n") == ["app/static", "vendor"]


def test_empty_rule_packs_give_the_default_set():
    assert scope.parse_rule_packs("  \n") == list(scope.DEFAULT_RULE_PACKS)


def test_rule_packs_split_on_spaces_and_newlines():
    assert scope.parse_rule_packs("python/lang/security  go/*/security\nhtml/security") == [
        "python/lang/security",
        "go/*/security",
        "html/security",
    ]


def test_rule_pack_globs_expand_inside_the_rules_tree(tmp_path):
    for pack in ("go/a/security", "go/b/security", "python/lang/security"):
        (tmp_path / pack).mkdir(parents=True)

    assert scope.expand_packs(tmp_path, ["go/*/security", "python/lang/security"]) == [
        tmp_path / "go/a/security",
        tmp_path / "go/b/security",
        tmp_path / "python/lang/security",
    ]


def test_a_missing_rule_pack_is_an_error(tmp_path):
    with pytest.raises(ScanError, match="opengrep rule pack not found: rust/\\*/security"):
        scope.expand_packs(tmp_path, ["rust/*/security"])


def test_bandit_skips_test_files_venv_and_excluded_paths():
    files = [
        "app.py",
        "tests/test_a.py",
        "pkg/tests/helper.py",
        "pkg/tests.py",
        "conftest.py",
        "pkg/a_test.py",
        "pkg/test_b.py",
        ".venv/lib/x.py",
        "vendor/y.py",
        "vendor",
        "vendorx/z.py",
    ]

    assert scope.bandit_targets(files, ["vendor"]) == ["app.py", "vendorx/z.py"]


def test_every_exclude_reaches_opengrep_trivy_and_osv(tmp_path):
    commands = scope.Commands(
        excludes=["app/static", "vendor"],
        rule_dirs=[tmp_path / "python"],
        reports=tmp_path,
    )

    opengrep = commands.opengrep("opengrep")
    trivy = commands.trivy("trivy")
    osv = commands.osv("osv-scanner")

    for path in ("app/static", "vendor"):
        assert opengrep[opengrep.index(path) - 1] == "--exclude"
        assert trivy[trivy.index(path) - 1] == "--skip-dirs"
        assert osv[osv.index(path) - 1] == "--experimental-exclude"
    assert f"--json-output={tmp_path / 'opengrep.json'}" in opengrep
