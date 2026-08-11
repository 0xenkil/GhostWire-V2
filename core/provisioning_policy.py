"""Shared install/run safety policy (P2-1, §3.4).

ONE authority for what may be PROVISIONED (installed) vs what may be EXECUTED,
used by both the guardian (run gate) and the tool installer (install gate).

The design contract (GUARDIAN-ALLOWLIST-1): the engine is autonomous — the AI may
pick ANY tool. Safety therefore comes from a SHORT deny list of genuinely
destructive/irreversible verbs, NOT from an allowlist of blessed tools (the
allowlist was the autonomy limiter — it blocked every modern recon tool nobody
had pre-registered). Read-only inspection commands (``crontab -l``, ``iptables
-L``, ``netstat``, ``ps``) are NOT denied; only the verbs that wipe disks, tear
down the host, or delete accounts are.
"""

# ── Never EXECUTE ────────────────────────────────────────────────────────────
# Short, destructive/irreversible binaries only. This is the authority the
# guardian consults now that the allowlist is gone; the pattern rails
# (BLOCKED_PATTERNS / DESTRUCTIVE_PATTERNS) still catch dangerous *invocations*
# like `rm -rf /` and `dd of=/dev/sda`.
RUN_DENY: frozenset = frozenset({
    "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
    "mkfs.vfat", "mkfs.fat", "mkswap",
    "fdisk", "sfdisk", "cfdisk", "parted", "gparted",
    "wipefs", "shred", "blkdiscard",
    "reboot", "shutdown", "halt", "poweroff", "init", "telinit",
    "userdel", "groupdel", "deluser", "delgroup",
})

# ── Never PROVISION (install) ────────────────────────────────────────────────
# Binaries the unattended provisioner must not fetch-and-run. Running an already
# present one is governed separately by RUN_DENY — this is only about install.
INSTALL_DENY: frozenset = frozenset({
    "dd", "mkfs", "fdisk", "parted", "meterpreter",
})

# ── Trusted install sources ──────────────────────────────────────────────────
# Prefixes the installer's source-audit (Gate-5) checks an install command/URL
# against. Kept DATA (widen by editing this list, never a core edit) so modern
# recon tools installed via go/pipx/GitHub releases are trusted.
TRUSTED_INSTALL_SOURCES: list = [
    "https://github.com/",
    "https://raw.githubusercontent.com/",
    "https://codeload.github.com/",
    "https://go.dev/", "https://proxy.golang.org/", "go install ",
    "https://pypi.org/", "https://files.pythonhosted.org/",
    "pipx install ", "pip install ", "pip3 install ", "python -m pip", "python3 -m pip",
    "apt-get install ", "apt install ", "apt-fast install ",
    "https://install.", "https://sh.rustup.rs", "cargo install ",
    "gem install ", "npm install ", "npm i ", "snap install ",
]


def _basename(name: str) -> str:
    return (name or "").strip().rsplit("/", 1)[-1].lower()


def is_run_blocked(binary: str) -> bool:
    """True iff ``binary`` is a destructive verb that must never be executed."""
    return _basename(binary) in RUN_DENY


def is_install_blocked(binary: str) -> bool:
    """True iff ``binary`` must never be auto-provisioned."""
    return _basename(binary) in INSTALL_DENY


def is_trusted_install_source(install_cmd_or_url: str) -> bool:
    """True iff an install command / URL begins with (or contains) a trusted
    source prefix — the installer's Gate-5 audit (data-driven, extensible)."""
    if not install_cmd_or_url:
        return False
    s = install_cmd_or_url.strip().lower()
    return any(src.lower() in s for src in TRUSTED_INSTALL_SOURCES)
