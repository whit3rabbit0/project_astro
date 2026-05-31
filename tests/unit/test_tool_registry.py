import pytest

from astro.tools.base import BaseTool
from astro.tools.registry import ToolCategory, ToolRegistry, create_default_registry


class StubTool(BaseTool):
    name = "stub"
    description = "stub tool"

    def validate(self, params):
        return params

    def build_command(self, params):
        return ["echo", "stub"]


class TestToolRegistry:
    def test_register_and_get(self):
        registry = ToolRegistry()
        tool = StubTool()
        registry.register(tool)
        assert registry.get("stub") is tool

    def test_get_raises_key_error_for_unknown_tool(self):
        registry = ToolRegistry()
        with pytest.raises(KeyError, match="Tool not found"):
            registry.get("nonexistent")

    def test_list_tools_returns_registered_names(self):
        registry = ToolRegistry()
        registry.register(StubTool())
        assert "stub" in registry.list_tools()

    def test_get_all_returns_dict(self):
        registry = ToolRegistry()
        tool = StubTool()
        registry.register(tool)
        all_tools = registry.get_all()
        assert isinstance(all_tools, dict)
        assert all_tools["stub"] is tool


class TestCreateDefaultRegistry:
    def test_returns_23_tools(self):
        registry = create_default_registry()
        assert len(registry.list_tools()) == 23

    def test_contains_nmap(self):
        registry = create_default_registry()
        tool = registry.get("nmap")
        assert tool.name == "nmap"

    def test_contains_sqlmap(self):
        registry = create_default_registry()
        tool = registry.get("sqlmap")
        assert tool.name == "sqlmap"

    def test_contains_custom_script(self):
        registry = create_default_registry()
        tool = registry.get("custom_script")
        assert tool.name == "custom_script"


class TestListByCategory:
    def test_filter_recon_tools(self):
        registry = create_default_registry()
        recon = registry.list_by_category(ToolCategory.RECON)
        assert "nmap" in recon
        assert "gobuster" in recon
        assert "sqlmap" not in recon

    def test_filter_exploitation_tools(self):
        registry = create_default_registry()
        exploit = registry.list_by_category(ToolCategory.EXPLOITATION)
        assert "sqlmap" in exploit
        assert "hydra" in exploit
        assert "nmap" not in exploit

    def test_filter_custom_tools(self):
        registry = create_default_registry()
        custom = registry.list_by_category(ToolCategory.CUSTOM)
        assert "custom_script" in custom


class TestGetCategories:
    def test_returns_all_category_keys(self):
        registry = create_default_registry()
        categories = registry.get_categories()
        assert "recon" in categories
        assert "exploitation" in categories
        assert "custom" in categories

    def test_each_category_has_tools(self):
        registry = create_default_registry()
        categories = registry.get_categories()
        for cat_name, tools in categories.items():
            assert len(tools) > 0, f"Category {cat_name} has no tools"
