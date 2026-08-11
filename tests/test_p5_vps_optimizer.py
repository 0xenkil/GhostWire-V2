"""Phase 5 — P5-3 vps_optimizer stub reduction (D-VPS-1 / VPS-OPT-STUBBED).

The four "_optimize_*" WSL methods did nothing but append "Skipped (WSL)" to
optimizations_applied — fake changes that made the optimizer look busy. And a
hardcoded run1/H3 debug side-channel (_load_debug_cfg / _agent_debug_log) wrote
JSON lines to a separate debug log. P5-3 deletes both; optimize_all() keeps only
the three methods that do real remote work, and diagnostics go through the logger.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.vps_optimizer as vps  # noqa: E402
from core.vps_optimizer import VPSOptimizer  # noqa: E402


class _FakeRemote:
    """Captures remote commands; returns a parseable df-style output."""
    def __init__(self):
        self.calls = []

    def execute(self, cmd, timeout=None):
        self.calls.append(cmd)
        return (0, "20,50", "")  # available_gb=20, total_gb=50


def test_side_channel_and_noops_are_gone():
    assert not hasattr(vps, "_agent_debug_log")
    assert not hasattr(vps, "_load_debug_cfg")
    for m in ("_optimize_ssh_maxsessions", "_optimize_file_descriptors",
              "_optimize_tcp_buffers", "_optimize_congestion_control"):
        assert not hasattr(VPSOptimizer, m), f"{m} should be deleted"


def test_only_real_work_methods_remain():
    for m in ("_prepare_scan_directories", "_cleanup_old_results",
              "_verify_disk_space", "optimize_all"):
        assert hasattr(VPSOptimizer, m), f"{m} must remain"


def test_optimize_all_runs_real_work_and_reports_no_fake_changes():
    opt = VPSOptimizer(_FakeRemote())
    assert opt.optimize_all() is True
    # The fake "Skipped (WSL)" entries must be gone entirely.
    assert not any("Skipped (WSL)" in c for c in opt.optimizations_applied)
    # Only genuine work is recorded.
    joined = " | ".join(opt.optimizations_applied)
    assert "Scan Directories" in joined
    assert "Disk Space: 20GB available" in joined


def test_optimizer_actually_issued_remote_commands():
    remote = _FakeRemote()
    VPSOptimizer(remote).optimize_all()
    # Real work means real remote calls (mkdir/find/df) — not zero.
    assert any("mkdir -p" in c for c in remote.calls)
    assert any(c.startswith("df ") for c in remote.calls)
