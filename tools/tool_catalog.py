"""tools/tool_catalog.py — the one capability-keyed tool catalog (P2-1 / P2-4).

A single catalog keyed by tool name, carrying each tool's primary capability, its
install command (the modern recon arsenal is Go-based → `go install`, which is
arch-correct — verified on ARM), and capability tags such as `needs_raw_socket`
(P2-1 amendment: the raw-socket identity is a CATALOG TAG, not a hardcoded set, so
a newly-registered raw-socket tool is routed/guarded correctly with no core edit).

NEW-6: `installed` is RUNTIME-ONLY and NEVER persisted — a persisted `installed:
True` lies after a fresh VPS or a wiped binary. The catalog only records WHAT a
tool is and HOW to install it; whether it is present is re-verified at runtime.
Persistence is atomic (temp + os.replace), shape-preserving, and drops any
`installed` key that sneaks into an on-disk file.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

_CATALOG_PATH = str(Path(__file__).resolve().parent.parent / "config" / "tool_catalog.json")


@dataclass(frozen=True)
class ToolEntry:
    name: str
    binary: str
    capabilities: tuple = ()          # capabilities[0] is the primary capability
    install: str = ""                 # e.g. "go install github.com/.../httpx@latest"
    needs_raw_socket: bool = False    # SOCKS/Tor cannot carry raw packets (routing tag)
    category: str = "recon"

    @property
    def primary_capability(self) -> str:
        return self.capabilities[0] if self.capabilities else ""


# Seed: modern recon arsenal. Go tools install via `go install` (arch-correct);
# raw-socket tools tagged so stealth/enforce_capability route them correctly.
_SEED = (
    ToolEntry("httpx", "httpx", ("http_probe",),
              "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolEntry("subfinder", "subfinder", ("subdomain_enum",),
              "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolEntry("nuclei", "nuclei", ("vuln_scan",),
              "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ToolEntry("katana", "katana", ("crawl",),
              "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolEntry("dnsx", "dnsx", ("dns_resolve",),
              "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", needs_raw_socket=True),
    ToolEntry("naabu", "naabu", ("port_scan",),
              "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", needs_raw_socket=True),
    ToolEntry("gau", "gau", ("url_discovery",),
              "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ToolEntry("nmap", "nmap", ("port_scan",),
              "apt-get install -y nmap", needs_raw_socket=True),
    ToolEntry("masscan", "masscan", ("port_scan",),
              "apt-get install -y masscan", needs_raw_socket=True),
    ToolEntry("dig", "dig", ("dns_resolve",),
              "apt-get install -y dnsutils", needs_raw_socket=True),
)


class ToolCatalog:
    def __init__(self, path: str = None):
        self._path = path or _CATALOG_PATH
        self._lock = threading.RLock()
        self._entries: dict[str, ToolEntry] = {}
        self._installed: set[str] = set()   # RUNTIME-only — never persisted (NEW-6)
        self._load()

    def _load(self):
        for e in _SEED:
            self._entries[e.name] = e
        try:
            if os.path.exists(self._path):
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for d in (data.get("tools", []) if isinstance(data, dict) else []):
                    if not isinstance(d, dict) or not d.get("name"):
                        continue
                    d.pop("installed", None)   # NEW-6: never trust a persisted installed
                    self._entries[d["name"]] = ToolEntry(
                        name=d["name"], binary=d.get("binary", d["name"]),
                        capabilities=tuple(d.get("capabilities", ())),
                        install=d.get("install", ""),
                        needs_raw_socket=bool(d.get("needs_raw_socket", False)),
                        category=d.get("category", "recon"))
        except Exception:
            pass   # a corrupt catalog falls back to the seed, never crashes

    # ── reads ────────────────────────────────────────────────────────────────
    def get(self, name: str) -> Optional[ToolEntry]:
        return self._entries.get((name or "").lower()) or self._entries.get(name or "")

    def all(self) -> list:
        return list(self._entries.values())

    def install_command(self, name: str) -> str:
        e = self.get(name)
        return e.install if e else ""

    def needs_raw_socket(self, name: str) -> bool:
        e = self.get(name)
        return bool(e and e.needs_raw_socket)

    def raw_socket_tools(self) -> set:
        return {e.name for e in self._entries.values() if e.needs_raw_socket}

    # ── runtime install state (NEVER persisted) ──────────────────────────────
    def mark_installed(self, name: str):
        with self._lock:
            self._installed.add((name or "").lower())

    def is_installed(self, name: str) -> bool:
        return (name or "").lower() in self._installed

    # ── registration + atomic persistence ────────────────────────────────────
    def register(self, entry: ToolEntry, persist: bool = True):
        with self._lock:
            self._entries[entry.name] = entry
            if persist:
                self._persist()

    def _persist(self):
        # Atomic + shape-preserving; `installed` is not a ToolEntry field so
        # asdict() can never write it.
        payload = {"tools": [asdict(e) for e in self._entries.values()]}
        for t in payload["tools"]:
            t["capabilities"] = list(t.get("capabilities", ()))
            t.pop("installed", None)
        tmp = self._path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, self._path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass


_catalog: Optional[ToolCatalog] = None
_catalog_lock = threading.Lock()


def get_catalog() -> ToolCatalog:
    global _catalog
    if _catalog is None:
        with _catalog_lock:
            if _catalog is None:
                _catalog = ToolCatalog()
    return _catalog
