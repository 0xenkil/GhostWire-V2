"""P2-4: the public registries are GENERATED VIEWS over private authored seeds
(_RAW_*) plus the ToolCatalog — one source of truth, deduped by binary. Authored
entries are preserved verbatim (zero behaviour change); catalog-only tools appear
automatically; register_tool still mutates the live view.
"""
from tools.tool_registry import TOOL_REGISTRY, _RAW_TOOL_REGISTRY, register_tool
from core.capability_registry import ALL_TOOLS, _RAW_ALL_TOOLS
from tools.tool_catalog import get_catalog


def test_tool_registry_is_a_superset_of_raw_seed():
    for k, v in _RAW_TOOL_REGISTRY.items():
        assert k in TOOL_REGISTRY
        assert TOOL_REGISTRY[k] == v            # authored entry preserved verbatim


def test_catalog_tools_appear_in_the_view():
    # every catalog tool is now visible in TOOL_REGISTRY (dedup by name)
    for e in get_catalog().all():
        assert e.name.lower() in TOOL_REGISTRY
    # and at least one modern tool was contributed BY the catalog (not the raw seed)
    added = set(TOOL_REGISTRY) - set(_RAW_TOOL_REGISTRY)
    assert added, "catalog contributed no new tools — view not merging"


def test_all_tools_is_a_generated_view_over_raw():
    raw = {(t.binary or t.name).lower() for t in _RAW_ALL_TOOLS}
    view = {(t.binary or t.name).lower() for t in ALL_TOOLS}
    assert raw <= view                          # nothing dropped
    # catalog tools are all represented
    for e in get_catalog().all():
        assert (e.binary or e.name).lower() in view


def test_register_tool_mutates_the_live_view():
    register_tool("unit_probe_tool", {"binary": "unit_probe_tool", "timeout": 7})
    assert TOOL_REGISTRY.get("unit_probe_tool", {}).get("timeout") == 7
