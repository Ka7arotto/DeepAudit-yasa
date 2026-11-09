"""Platform resolution and offline installer regression tests."""
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from app.services.yasa_audit import config


@pytest.mark.parametrize("system,machine,expected", [
    ("Darwin", "arm64", "darwin-aarch64"),
    ("Darwin", "aarch64", "darwin-aarch64"),
    ("Darwin", "x86_64", "darwin-x86-64"),
    ("Linux", "x86_64", "linux-x86-64"),
])
def test_native_tool_paths(monkeypatch, tmp_path, system, machine, expected):
    monkeypatch.setattr(config.platform, "system", lambda: system)
    monkeypatch.setattr(config.platform, "machine", lambda: machine)
    assert config.platform_directory() == expected
    monkeypatch.setattr(config, "DEFAULT_TOOLS", tmp_path / "tools" / expected)
    for name in ("YASA_RG_BIN", "YASA_CODEGRAPH_BIN"):
        monkeypatch.delenv(name, raising=False)
    cfg = config.AuditConfig()
    assert cfg.rg_bin == str(tmp_path / "tools" / expected / "ripgrep/rg")
    assert cfg.codegraph_bin == str(tmp_path / "tools" / expected / "codegraph/bin/codegraph")
    monkeypatch.setenv("YASA_RG_BIN", "/custom/rg")
    monkeypatch.setenv("YASA_CODEGRAPH_BIN", "/custom/codegraph")
    cfg = config.AuditConfig()
    assert (cfg.rg_bin, cfg.codegraph_bin) == ("/custom/rg", "/custom/codegraph")


def test_tool_home_prefers_yasa_home(monkeypatch, tmp_path):
    import importlib
    monkeypatch.setenv("YASAMCP_HOME", str(tmp_path / "old"))
    monkeypatch.delenv("YASA_HOME", raising=False)
    assert importlib.reload(config).DEFAULT_HOME == tmp_path / "old"
    monkeypatch.setenv("YASA_HOME", str(tmp_path / "new"))
    assert importlib.reload(config).DEFAULT_HOME == tmp_path / "new"
    monkeypatch.delenv("YASA_HOME")
    monkeypatch.delenv("YASAMCP_HOME")
    importlib.reload(config)


def _executable(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    path.chmod(0o755)


@pytest.fixture
def installer(tmp_path):
    """Fake only uname and downloads; exercise real extraction, checksum and validation."""
    bindir = tmp_path / "bin"
    _executable(bindir / "uname", '#!/bin/sh\ncase "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac\n')
    _executable(bindir / "curl", f'''#!{sys.executable}
import os, pathlib, shutil, sys
args=sys.argv[1:]
url=args[-1]
dest=args[args.index('-o')+1]
with open(os.environ['DOWNLOAD_LOG'], 'a') as log: log.write(url+'\\n')
shutil.copyfile(pathlib.Path(os.environ['FIXTURES']) / url.rsplit('/',1)[-1], dest)
''')
    env = os.environ.copy()
    env.update(PATH=f"{bindir}:{env['PATH']}", PYTHON=sys.executable,
               YASA_HOME=str(tmp_path / "install"), FIXTURES=str(tmp_path / "fixtures"),
               DOWNLOAD_LOG=str(tmp_path / "downloads.txt"))
    env.pop("YASAMCP_HOME", None)
    script = Path(__file__).resolve().parents[1] / "scripts/setup_yasa.sh"
    return script, env, tmp_path


@pytest.mark.parametrize("system,machine,plat", [
    ("Darwin", "arm64", "darwin-aarch64"),
    ("Darwin", "aarch64", "darwin-aarch64"),
    ("Darwin", "x86_64", "darwin-x86-64"),
    ("Linux", "x86_64", "linux-x86-64"),
])
def test_installer_platform_and_reuse(installer, system, machine, plat):
    script, env, root = installer
    fixtures = Path(env["FIXTURES"])
    fixtures.mkdir()
    with zipfile.ZipFile(fixtures / f"{plat}.zip", "w") as archive:
        for rel in ("yasa/yasa", "ripgrep/rg", "scc/scc", "codegraph/bin/codegraph", "codegraph/node"):
            archive.writestr(f"{plat}/{rel}", "#!/bin/sh\nexit 0\n")
    env.update(TEST_OS=system, TEST_ARCH=machine)
    first = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert first.returncode == 0, first.stdout + first.stderr
    tools = Path(env["YASA_HOME"]) / "tools" / plat
    assert os.access(tools / "codegraph/bin/codegraph", os.X_OK) and os.access(tools / "ripgrep/rg", os.X_OK)
    assert os.access(tools / "codegraph/node", os.X_OK)
    assert not (tools / "yasa").exists()  # the unused engine is not kept
    downloads = Path(env["DOWNLOAD_LOG"]).read_text()
    assert downloads.strip().endswith(f"/{plat}.zip") and len(downloads.splitlines()) == 1
    second = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert second.returncode == 0, second.stdout + second.stderr
    assert Path(env["DOWNLOAD_LOG"]).read_text() == downloads  # installed tools are reused


def test_unsupported_installer_platform(installer):
    script, env, root = installer
    env.update(TEST_OS="Linux", TEST_ARCH="aarch64")
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode != 0 and "unsupported platform" in result.stderr
    assert not Path(env["DOWNLOAD_LOG"]).exists()
    assert not Path(env["YASA_HOME"]).exists()
