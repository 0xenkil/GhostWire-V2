"""Phase 2 — P2-1 ToolCatalog + P2-4 seed + NEW-6 (installed never persisted)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.tool_catalog import ToolCatalog, ToolEntry  # noqa: E402


def _cat():
    return ToolCatalog(path=os.path.join(tempfile.mkdtemp(), "catalog.json"))


def test_seed_has_modern_recon_arsenal_with_go_install():
    cat = _cat()
    for name in ("httpx", "subfinder", "nuclei", "katana", "dnsx", "naabu", "gau"):
        e = cat.get(name)
        assert e is not None, f"{name} missing from catalog"
        assert e.install, f"{name} has no install command"
    # Go tools install via `go install` (arch-correct).
    assert cat.install_command("httpx").startswith("go install ")


def test_raw_socket_is_a_catalog_tag():
    cat = _cat()
    assert cat.needs_raw_socket("nmap") is True
    assert cat.needs_raw_socket("masscan") is True
    assert cat.needs_raw_socket("naabu") is True
    assert cat.needs_raw_socket("httpx") is False
    assert "nmap" in cat.raw_socket_tools()


def test_newly_registered_raw_socket_tool_routed_without_core_edit():
    cat = _cat()
    cat.register(ToolEntry("zmap", "zmap", ("port_scan",),
                           "apt-get install -y zmap", needs_raw_socket=True))
    assert cat.needs_raw_socket("zmap") is True


def test_installed_is_runtime_only_never_persisted():
    path = os.path.join(tempfile.mkdtemp(), "catalog.json")
    cat = ToolCatalog(path=path)
    cat.mark_installed("httpx")
    assert cat.is_installed("httpx") is True
    cat.register(ToolEntry("newtool", "newtool", ("x",), "apt-get install -y newtool"))
    # Persisted file must NOT carry any `installed` flag (NEW-6).
    with open(path) as f:
        data = json.load(f)
    assert data["tools"]
    assert all("installed" not in t for t in data["tools"])
    # A fresh catalog from disk considers nothing installed until re-verified.
    fresh = ToolCatalog(path=path)
    assert fresh.is_installed("httpx") is False


def test_persist_is_atomic_and_reloads():
    path = os.path.join(tempfile.mkdtemp(), "catalog.json")
    ToolCatalog(path=path).register(
        ToolEntry("mytool", "mybin", ("cap1",), "go install x@latest"))
    reloaded = ToolCatalog(path=path)
    e = reloaded.get("mytool")
    assert e is not None and e.binary == "mybin" and e.capabilities == ("cap1",)


def test_corrupt_catalog_falls_back_to_seed():
    path = os.path.join(tempfile.mkdtemp(), "catalog.json")
    with open(path, "w") as f:
        f.write("{ this is not valid json ")
    cat = ToolCatalog(path=path)  # must not raise
    assert cat.get("nmap") is not None
