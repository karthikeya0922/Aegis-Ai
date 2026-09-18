"""aegis scan: findings, masking, baselines, git modes, SARIF, exit codes.

Fixtures are assembled at runtime so no credential-shaped literal sits in the
repository (same rule as the backend tests).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis_cli import scan as S
from aegis_cli.app import app
from aegis_cli.local import mask, scan_text

runner = CliRunner()


def _joined(*parts: str) -> str:
    return "".join(parts)


AWS = _joined("AKIA", "IOSFODNN7EXAMPLE")
SLACK = _joined("xoxb-", "123456789012-abcdefghijklmnop")
GH = _joined("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789")


# ---------------------------------------------------------------------------
# scan_text
# ---------------------------------------------------------------------------


def test_findings_have_line_numbers_and_never_the_value():
    text = f'OK = "x"\nKEY = "{AWS}"\n'
    out = scan_text("cfg.py", text)
    assert len(out) == 1
    f = out[0]
    assert (f.line, f.column) == (2, 8) and f.type == "AWS_ACCESS_KEY" and f.category == "SECRET"
    assert f.action == "block"
    assert AWS not in f.preview and f.preview.startswith("AKIA") and "*" in f.preview
    assert AWS not in json.dumps(f.__dict__)


def test_inline_allow_marker_is_recorded_not_hidden():
    out = scan_text("cfg.py", f'T = "{GH}"  # aegis:allow\n')
    assert len(out) == 1 and out[0].allowed_inline is True


def test_entropy_does_not_double_report_a_recognised_secret():
    out = scan_text("cfg.py", f'KEY = "{AWS}"\n')
    assert [f.category for f in out] == ["SECRET"]


@pytest.mark.parametrize("v,expect_prefix", [("short", "*****"), ("abcdefghij", "ab"), (AWS, "AKIA")])
def test_mask_shapes(v, expect_prefix):
    m = mask(v)
    assert m.startswith(expect_prefix) and v not in m or len(v) <= 8


# ---------------------------------------------------------------------------
# run_scan / exit codes / baseline
# ---------------------------------------------------------------------------


def test_fail_on_controls_exit_code():
    src = [("a.py", f'K = "{AWS}"\n'), ("b.txt", "high entropy: " + "kJ8f3Lq9ZxT2vB7nRw4pYs6dHc1mGe5a" + "\n")]
    res = S.run_scan(src, profile="default", pii=False, fail_on="secret")
    assert res.exit_code == 1 and {f.category for f in res.failing} == {"SECRET"}
    res_any = S.run_scan(src, profile="default", pii=False, fail_on="any")
    assert {f.category for f in res_any.findings} >= {"SECRET"}


def test_baseline_suppresses_by_fingerprint(tmp_path: Path):
    src = [("a.py", f'K = "{AWS}"\n')]
    first = S.run_scan(src, profile="default", pii=False, fail_on="secret")
    bl = tmp_path / "b.json"
    S.write_baseline(bl, first.findings)
    assert AWS not in bl.read_text()
    second = S.run_scan(src, profile="default", pii=False, fail_on="secret", baseline=S.load_baseline(bl))
    assert second.exit_code == 0 and second.suppressed_baseline == 1
    # a different value at the same place is a new finding
    third = S.run_scan([("a.py", f'K = "{SLACK}"\n')], profile="default", pii=False, fail_on="secret",
                       baseline=S.load_baseline(bl))
    assert third.exit_code == 1


def test_sarif_is_well_formed_and_valueless():
    res = S.run_scan([("a.py", f'K = "{AWS}"\n')], profile="default", pii=False, fail_on="secret")
    sarif = S.to_sarif(res, "0.0-test")
    assert sarif["version"] == "2.1.0"
    r = sarif["runs"][0]["results"][0]
    assert r["level"] == "error" and r["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert AWS not in json.dumps(sarif)


# ---------------------------------------------------------------------------
# git modes
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "clean.py").write_text('X = 1\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    return tmp_path


def test_staged_reads_the_index_not_the_working_tree(repo: Path):
    f = repo / "cfg.py"
    f.write_text(f'K = "{AWS}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "cfg.py"], cwd=repo, check=True)
    f.write_text('K = "removed"\n', encoding="utf-8")  # unstaged edit must not hide the staged secret
    staged = S.staged_files(repo)
    assert [p for p, _ in staged] == ["cfg.py"] and AWS in staged[0][1]


def test_diff_scans_only_added_lines(repo: Path):
    f = repo / "cfg.py"
    f.write_text(f'A = "{AWS}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "cfg.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "one"], cwd=repo, check=True)
    f.write_text(f'A = "{AWS}"\nB = "{SLACK}"\n', encoding="utf-8")
    added = S.diff_added_lines("HEAD", repo)
    assert added == {"cfg.py": {2}}
    res = S.run_scan([("cfg.py", f.read_text())], profile="default", pii=False, fail_on="secret", only_lines=added)
    assert [x.type for x in res.findings] == ["SLACK_TOKEN"]


def test_hook_install_and_refusal(repo: Path, monkeypatch):
    from aegis_cli import hook as H

    path, status = H.install(repo)
    assert status == "installed" and H.HOOK_MARKER in path.read_text()
    assert H.install(repo)[1] == "replaced"
    # a foreign hook is not clobbered without --force
    path.write_text("#!/bin/sh\necho mine\n")
    with pytest.raises(FileExistsError):
        H.install(repo)
    assert H.install(repo, force=True)[1] == "replaced"

    # the CLI itself, as the hook would call it
    (repo / "leak.py").write_text(f'K = "{AWS}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "leak.py"], cwd=repo, check=True)
    monkeypatch.chdir(repo)
    r = runner.invoke(app, ["scan", "--staged", "--hook"])
    assert r.exit_code == 1 and "Commit refused" in r.output and AWS not in r.output
    assert H.uninstall(repo) is True


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_json_and_bad_args(tmp_path: Path):
    (tmp_path / "a.py").write_text(f'K = "{AWS}"\n', encoding="utf-8")
    r = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert r.exit_code == 1
    body = json.loads(r.output)
    assert body["failing"] == 1 and AWS not in r.output and body["disclaimer"].startswith("Heuristic")
    assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "everything"]).exit_code == 2
    assert runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"]).exit_code == 2


def test_cli_clean_dir_exits_zero(tmp_path: Path):
    (tmp_path / "a.py").write_text("print('hello')\n", encoding="utf-8")
    r = runner.invoke(app, ["scan", str(tmp_path)])
    assert r.exit_code == 0 and "0 failing" in r.output


def test_version_and_config():
    assert "aegis-cli" in runner.invoke(app, ["--version"]).output
    r = runner.invoke(app, ["config", "--json"])
    assert r.exit_code == 0 and "engine_url" in r.output
