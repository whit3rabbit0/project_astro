"""Registry of available tools, organised by category."""
from enum import Enum

from astro.tools.base import BaseTool


class ToolCategory(str, Enum):
    RECON = "recon"
    EXPLOITATION = "exploitation"
    CUSTOM = "custom"


TOOL_CATEGORIES: dict[str, ToolCategory] = {
    # Recon
    "nmap": ToolCategory.RECON,
    "gobuster": ToolCategory.RECON,
    "dirb": ToolCategory.RECON,
    "nikto": ToolCategory.RECON,
    "wpscan": ToolCategory.RECON,
    "enum4linux": ToolCategory.RECON,
    "subfinder": ToolCategory.RECON,
    "amass": ToolCategory.RECON,
    "ffuf": ToolCategory.RECON,
    "whatweb": ToolCategory.RECON,
    "dnsrecon": ToolCategory.RECON,
    "theharvester": ToolCategory.RECON,
    # Exploitation
    "sqlmap": ToolCategory.EXPLOITATION,
    "metasploit": ToolCategory.EXPLOITATION,
    "hydra": ToolCategory.EXPLOITATION,
    "john": ToolCategory.EXPLOITATION,
    "searchsploit": ToolCategory.EXPLOITATION,
    "crackmapexec": ToolCategory.EXPLOITATION,
    "hashcat": ToolCategory.EXPLOITATION,
    "responder": ToolCategory.EXPLOITATION,
    "smbclient": ToolCategory.EXPLOITATION,
    "evil-winrm": ToolCategory.EXPLOITATION,
    # Custom
    "custom_script": ToolCategory.CUSTOM,
}


class ToolRegistry:
    """Registry of available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        if name not in self._tools:
            raise KeyError(f"Tool not found: {name!r}")
        return self._tools[name]

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    def get_all(self) -> dict[str, BaseTool]:
        return dict(self._tools)

    def list_by_category(self, category: ToolCategory) -> list[str]:
        """Return registered tool names filtered by category."""
        return [name for name in self._tools if TOOL_CATEGORIES.get(name) == category]

    def get_categories(self) -> dict[str, list[str]]:
        """Return all registered tools organised by category."""
        result: dict[str, list[str]] = {}
        for cat in ToolCategory:
            tools = self.list_by_category(cat)
            if tools:
                result[cat.value] = tools
        return result


def create_default_registry() -> ToolRegistry:
    """Create a registry pre-loaded with all 23 built-in tools."""
    from astro.tools.nmap import NmapTool
    from astro.tools.gobuster import GobusterTool
    from astro.tools.dirb import DirbTool
    from astro.tools.nikto import NiktoTool
    from astro.tools.sqlmap import SqlmapTool
    from astro.tools.metasploit import MetasploitTool
    from astro.tools.hydra import HydraTool
    from astro.tools.john import JohnTool
    from astro.tools.wpscan import WpscanTool
    from astro.tools.enum4linux import Enum4linuxTool
    from astro.tools.subfinder import SubfinderTool
    from astro.tools.amass import AmassTool
    from astro.tools.ffuf import FfufTool
    from astro.tools.whatweb import WhatwebTool
    from astro.tools.dnsrecon import DnsreconTool
    from astro.tools.theharvester import TheHarvesterTool
    from astro.tools.searchsploit import SearchsploitTool
    from astro.tools.crackmapexec import CrackMapExecTool
    from astro.tools.hashcat import HashcatTool
    from astro.tools.responder import ResponderTool
    from astro.tools.smbclient import SmbclientTool
    from astro.tools.evil_winrm import EvilWinrmTool
    from astro.tools.custom_script import CustomScriptTool

    registry = ToolRegistry()
    for tool in (
        NmapTool(),
        GobusterTool(),
        DirbTool(),
        NiktoTool(),
        SqlmapTool(),
        MetasploitTool(),
        HydraTool(),
        JohnTool(),
        WpscanTool(),
        Enum4linuxTool(),
        SubfinderTool(),
        AmassTool(),
        FfufTool(),
        WhatwebTool(),
        DnsreconTool(),
        TheHarvesterTool(),
        SearchsploitTool(),
        CrackMapExecTool(),
        HashcatTool(),
        ResponderTool(),
        SmbclientTool(),
        EvilWinrmTool(),
        CustomScriptTool(),
    ):
        registry.register(tool)
    return registry
