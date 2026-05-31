"""Project Astro V2 — MCP server using the official MCP Python SDK.

This is the core of V2. All 10 penetration testing tools are registered as MCP
tools, together with engagement-management helpers, prompts, and resources.
"""

from __future__ import annotations

import json
from typing import Any

import os

import structlog
from mcp.server.fastmcp import FastMCP

from astro.core import EngagementManager, RateLimiter, ScopeEnforcer, ToolExecutor
from astro.core.auth import AuthManager
from astro.tools import ToolCategory, create_default_registry

logger = structlog.get_logger(__name__)

# NOTE: FastMCP does not natively support CORS configuration. In production,
# a reverse proxy (e.g. nginx, Caddy) MUST enforce CORS with allowed origins
# restricted to localhost / trusted domains only.
mcp = FastMCP(
    "Project Astro",
    host=os.environ.get("ASTRO_HOST", "127.0.0.1"),
    port=int(os.environ.get("ASTRO_PORT", "8080")),
)

# Module-level singletons — set by initialize_server() at startup.
_executor: ToolExecutor | None = None
_scope: ScopeEnforcer | None = None
_engagement: EngagementManager | None = None
_current_engagement_id: str | None = None
_registry = create_default_registry()
_rate_limiter: RateLimiter | None = None
_auth: AuthManager | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _run_tool(tool_key: str, params: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool through the registry and optionally record findings."""
    if _scope:
        target = params.get("target") or params.get("url") or ""
        if target:
            _scope.validate_target(target)

        # Check host parameter (netcat, chisel, etc.)
        host_param = params.get("host") or ""
        if host_param:
            _scope.validate_target(host_param)

        # Check target_url parameter (burp, etc.)
        target_url_param = params.get("target_url") or ""
        if target_url_param:
            _scope.validate_target(target_url_param)

        # Check Metasploit options for target parameters
        options = params.get("options")
        if isinstance(options, dict):
            for opt_key in ("RHOSTS", "RHOST", "LHOST"):
                opt_val = options.get(opt_key) or ""
                if opt_val:
                    _scope.validate_target(opt_val)

    tool = _registry.get(tool_key)

    if _rate_limiter:
        async with _rate_limiter.acquire(tool_key):
            result = await tool.execute(_executor, params)
    else:
        result = await tool.execute(_executor, params)

    if _engagement and _current_engagement_id:
        await _engagement.record_finding(
            _current_engagement_id,
            tool_key,
            params.get("target") or params.get("url") or "",
            {k: v for k, v in params.items() if k not in ("target", "url")},
            result.raw,
            result.parsed,
        )

    dumped: dict[str, Any] = result.model_dump()
    return dumped


# ---------------------------------------------------------------------------
# Penetration testing tools — all 10
# ---------------------------------------------------------------------------


@mcp.tool()
async def nmap_scan(
    target: str,
    scan_type: str = "-sV",
    ports: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run nmap network scanner.

    Returns structured host/port/service data with optional CVE correlation.

    Args:
        target: IP address, hostname, or CIDR range to scan.
        scan_type: Nmap scan flags (default: -sV for version detection).
        ports: Comma-separated port list or range (e.g. '80,443' or '1-1024').
        additional_args: Extra nmap flags (e.g. '-T4 -A').
    """
    logger.info("nmap_scan called", target=target, scan_type=scan_type)
    return await _run_tool(
        "nmap",
        {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args},
    )


@mcp.tool()
async def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run gobuster directory/file/DNS brute-forcer.

    Args:
        url: Target URL (e.g. http://10.10.10.10).
        mode: Scan mode — 'dir', 'dns', or 'vhost'.
        wordlist: Absolute path to wordlist file.
        extensions: Comma-separated file extensions to test (e.g. 'php,html').
        additional_args: Extra gobuster flags.
    """
    logger.info("gobuster_scan called", url=url, mode=mode)
    return await _run_tool(
        "gobuster",
        {"url": url, "mode": mode, "wordlist": wordlist, "extensions": extensions, "additional_args": additional_args},
    )


@mcp.tool()
async def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run dirb web content scanner.

    Args:
        url: Target URL (e.g. http://10.10.10.10).
        wordlist: Absolute path to wordlist file.
        additional_args: Extra dirb flags.
    """
    logger.info("dirb_scan called", url=url)
    return await _run_tool(
        "dirb",
        {"url": url, "wordlist": wordlist, "additional_args": additional_args},
    )


@mcp.tool()
async def nikto_scan(
    target: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run nikto web server vulnerability scanner.

    Args:
        target: Target URL or host (e.g. http://10.10.10.10 or 10.10.10.10).
        additional_args: Extra nikto flags (e.g. '-Tuning 1234' for tuning classes).
    """
    logger.info("nikto_scan called", target=target)
    return await _run_tool(
        "nikto",
        {"target": target, "additional_args": additional_args},
    )


@mcp.tool()
async def sqlmap_scan(
    url: str,
    data: str = "",
    dbs: bool = False,
    tables: bool = False,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run sqlmap SQL injection tester.

    Args:
        url: Target URL (e.g. http://10.10.10.10/login.php?id=1).
        data: POST data string for form-based injection testing.
        dbs: Enumerate available databases when True.
        tables: Enumerate tables when True.
        additional_args: Extra sqlmap flags (e.g. '--level 3 --risk 2').
    """
    logger.info("sqlmap_scan called", url=url)
    return await _run_tool(
        "sqlmap",
        {"url": url, "data": data, "dbs": dbs, "tables": tables, "additional_args": additional_args},
    )


@mcp.tool()
async def metasploit_run(
    module: str,
    options: dict[str, str] | None = None,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run a Metasploit module.

    Args:
        module: Module path (e.g. 'exploit/multi/http/apache_struts2_content_type_rce').
        options: Module options dict (e.g. {'RHOSTS': '10.10.10.10', 'LHOST': '10.10.14.1'}).
        additional_args: Extra msfconsole flags.
    """
    logger.info("metasploit_run called", module=module)
    return await _run_tool(
        "metasploit",
        {"module": module, "options": options or {}, "additional_args": additional_args},
    )


@mcp.tool()
async def hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password_file: str = "/usr/share/wordlists/rockyou.txt",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run hydra password brute-forcer.

    Args:
        target: Target IP or hostname.
        service: Service to attack (e.g. 'ssh', 'ftp', 'http-post-form').
        username: Single username to test.
        username_file: Path to username list file (mutually exclusive with username).
        password_file: Path to password list file.
        additional_args: Extra hydra flags (e.g. '-t 4' to limit threads).
    """
    logger.info("hydra_attack called", target=target, service=service)
    return await _run_tool(
        "hydra",
        {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password_file": password_file,
            "additional_args": additional_args,
        },
    )


@mcp.tool()
async def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run John the Ripper password cracker.

    Args:
        hash_file: Absolute path to the hash file.
        wordlist: Absolute path to wordlist file.
        format: Hash format identifier (e.g. 'md5crypt', 'sha512crypt', 'ntlm').
        additional_args: Extra john flags.
    """
    logger.info("john_crack called", hash_file=hash_file, format=format)
    return await _run_tool(
        "john",
        {"hash_file": hash_file, "wordlist": wordlist, "format": format, "additional_args": additional_args},
    )


@mcp.tool()
async def wpscan_scan(
    url: str,
    enumerate: str = "u,p,t",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run WPScan WordPress vulnerability scanner.

    Args:
        url: Target WordPress site URL.
        enumerate: Enumeration flags (u=users, p=plugins, t=themes, default: 'u,p,t').
        additional_args: Extra wpscan flags (e.g. '--api-token TOKEN').
    """
    logger.info("wpscan_scan called", url=url)
    return await _run_tool(
        "wpscan",
        {"url": url, "enumerate": enumerate, "additional_args": additional_args},
    )


@mcp.tool()
async def enum4linux_scan(
    target: str,
    additional_args: str = "-a",
) -> dict[str, Any]:
    """Run enum4linux Windows/Samba enumeration tool.

    Args:
        target: Target IP address or hostname.
        additional_args: Extra enum4linux flags (default: '-a' for all enumeration).
    """
    logger.info("enum4linux_scan called", target=target)
    return await _run_tool(
        "enum4linux",
        {"target": target, "additional_args": additional_args},
    )


# ---------------------------------------------------------------------------
# Recon tools — new additions
# ---------------------------------------------------------------------------


@mcp.tool()
async def subfinder_scan(
    domain: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run subfinder passive subdomain discovery.

    Args:
        domain: Target domain to enumerate (e.g. 'example.com').
        additional_args: Extra subfinder flags.
    """
    logger.info("subfinder_scan called", domain=domain)
    return await _run_tool(
        "subfinder",
        {"domain": domain, "additional_args": additional_args},
    )


@mcp.tool()
async def amass_scan(
    domain: str,
    mode: str = "enum",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run amass in-depth DNS enumeration.

    Args:
        domain: Target domain to enumerate (e.g. 'example.com').
        mode: Amass mode — 'enum' (active) or 'intel' (passive intelligence).
        additional_args: Extra amass flags.
    """
    logger.info("amass_scan called", domain=domain, mode=mode)
    return await _run_tool(
        "amass",
        {"domain": domain, "mode": mode, "additional_args": additional_args},
    )


@mcp.tool()
async def ffuf_scan(
    url: str,
    wordlist: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run ffuf fast web fuzzer.

    Args:
        url: Target URL containing the FUZZ keyword (e.g. 'http://10.10.10.10/FUZZ').
        wordlist: Absolute path to wordlist file.
        additional_args: Extra ffuf flags (e.g. '-mc 200,301').
    """
    logger.info("ffuf_scan called", url=url)
    return await _run_tool(
        "ffuf",
        {"url": url, "wordlist": wordlist, "additional_args": additional_args},
    )


@mcp.tool()
async def whatweb_scan(
    target: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run WhatWeb web technology fingerprinting.

    Args:
        target: Target URL or hostname (e.g. 'http://10.10.10.10').
        additional_args: Extra whatweb flags (e.g. '-a 3' for aggressive mode).
    """
    logger.info("whatweb_scan called", target=target)
    return await _run_tool(
        "whatweb",
        {"target": target, "additional_args": additional_args},
    )


@mcp.tool()
async def dnsrecon_scan(
    domain: str,
    scan_type: str = "std",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run dnsrecon DNS reconnaissance.

    Args:
        domain: Target domain (e.g. 'example.com').
        scan_type: Scan type — 'std', 'brt' (brute), 'rvl' (reverse), or 'axfr' (zone transfer).
        additional_args: Extra dnsrecon flags.
    """
    logger.info("dnsrecon_scan called", domain=domain, scan_type=scan_type)
    return await _run_tool(
        "dnsrecon",
        {"domain": domain, "scan_type": scan_type, "additional_args": additional_args},
    )


@mcp.tool()
async def theharvester_scan(
    domain: str,
    source: str = "all",
    limit: str = "500",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run theHarvester email and subdomain OSINT harvesting.

    Args:
        domain: Target domain (e.g. 'example.com').
        source: Data source — 'all', 'google', 'bing', 'linkedin', 'shodan', etc.
        limit: Maximum number of results to retrieve (default: '500').
        additional_args: Extra theHarvester flags.
    """
    logger.info("theharvester_scan called", domain=domain, source=source)
    return await _run_tool(
        "theharvester",
        {"domain": domain, "source": source, "limit": limit, "additional_args": additional_args},
    )


# ---------------------------------------------------------------------------
# Exploitation tools — new additions
# ---------------------------------------------------------------------------


@mcp.tool()
async def searchsploit_search(
    query: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Search Exploit-DB local copy for exploits.

    Args:
        query: Search query — service name, CVE ID, or product (e.g. 'Apache 2.4').
        additional_args: Extra searchsploit flags (e.g. '--www' for web links).
    """
    logger.info("searchsploit_search called", query=query)
    return await _run_tool(
        "searchsploit",
        {"query": query, "additional_args": additional_args},
    )


@mcp.tool()
async def crackmapexec_run(
    protocol: str,
    target: str,
    username: str = "",
    password: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run CrackMapExec for AD/SMB credential testing and lateral movement.

    Args:
        protocol: Target protocol — 'smb', 'ssh', 'winrm', 'ldap', 'mssql', 'rdp', or 'ftp'.
        target: Target IP, hostname, or CIDR range.
        username: Username to authenticate with.
        password: Password to authenticate with.
        additional_args: Extra CrackMapExec flags (e.g. '--shares', '--users').
    """
    logger.info("crackmapexec_run called", protocol=protocol, target=target)
    return await _run_tool(
        "crackmapexec",
        {
            "protocol": protocol,
            "target": target,
            "username": username,
            "password": password,
            "additional_args": additional_args,
        },
    )


@mcp.tool()
async def hashcat_crack(
    hash_file: str,
    wordlist: str = "",
    hash_type: str = "0",
    attack_mode: str = "0",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run hashcat GPU-accelerated password cracking.

    Args:
        hash_file: Absolute path to the file containing hashes.
        wordlist: Absolute path to wordlist file (required for attack modes 0/6/7).
        hash_type: Hashcat hash-type number (e.g. '0'=MD5, '1000'=NTLM, '1800'=sha512crypt).
        attack_mode: Attack mode — '0' (dictionary), '1' (combination), '3' (brute-force).
        additional_args: Extra hashcat flags (e.g. '--rules-file /path/to/rules').
    """
    logger.info("hashcat_crack called", hash_file=hash_file, hash_type=hash_type)
    return await _run_tool(
        "hashcat",
        {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "hash_type": hash_type,
            "attack_mode": attack_mode,
            "additional_args": additional_args,
        },
    )


@mcp.tool()
async def responder_listen(
    interface: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """Run Responder LLMNR/NBT-NS/MDNS poisoner for credential capture.

    Args:
        interface: Network interface to listen on (e.g. 'eth0', 'tun0').
        additional_args: Extra responder flags (e.g. '-w' for WPAD rogue proxy).
    """
    logger.info("responder_listen called", interface=interface)
    return await _run_tool(
        "responder",
        {"interface": interface, "additional_args": additional_args},
    )


@mcp.tool()
async def smbclient_connect(
    target: str,
    username: str = "",
    password: str = "",
    command: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run smbclient to access SMB/CIFS shares.

    Args:
        target: SMB share path (e.g. '//10.10.10.10/share').
        username: Username for authentication.
        password: Password for authentication.
        command: SMB commands to execute (e.g. 'ls; get file.txt').
        additional_args: Extra smbclient flags.
    """
    logger.info("smbclient_connect called", target=target)
    return await _run_tool(
        "smbclient",
        {
            "target": target,
            "username": username,
            "password": password,
            "command": command,
            "additional_args": additional_args,
        },
    )


@mcp.tool()
async def evil_winrm_exec(
    target: str,
    username: str,
    password: str = "",
    hash: str = "",
    command: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """Run Evil-WinRM for Windows WinRM lateral movement and post-exploitation.

    Args:
        target: Target IP or hostname.
        username: Windows username.
        password: Plaintext password (mutually exclusive with hash).
        hash: NTLM hash for pass-the-hash (LM:NT or NT-only format).
        command: Command to execute on the remote host.
        additional_args: Extra evil-winrm flags.
    """
    logger.info("evil_winrm_exec called", target=target, username=username)
    return await _run_tool(
        "evil-winrm",
        {
            "target": target,
            "username": username,
            "password": password,
            "hash": hash,
            "command": command,
            "additional_args": additional_args,
        },
    )


# ---------------------------------------------------------------------------
# Custom script executor
# ---------------------------------------------------------------------------


@mcp.tool()
async def run_custom_script(
    script: str,
    language: str = "bash",
    timeout: int = 120,
) -> dict[str, Any]:
    """Execute a custom Python or Bash script for maximum flexibility.

    Args:
        script: Script source code to execute.
        language: Interpreter to use — 'bash' or 'python'.
        timeout: Execution timeout in seconds (1–600, default: 120).
    """
    logger.info("run_custom_script called", language=language, timeout=timeout)
    return await _run_tool(
        "custom_script",
        {"script": script, "language": language, "timeout": timeout},
    )


# ---------------------------------------------------------------------------
# Tool discovery helper
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_available_tools(category: str = "") -> dict[str, Any]:
    """List all available tools, optionally filtered by category.

    Args:
        category: Category to filter by — 'recon', 'exploitation', or 'custom'.
                  Empty string returns all tools grouped by category.
    """
    if category:
        try:
            cat = ToolCategory(category)
        except ValueError:
            valid = ", ".join(c.value for c in ToolCategory)
            return {"status": "error", "message": f"Unknown category {category!r}. Valid: {valid}"}
        tools = _registry.list_by_category(cat)
        return {"status": "ok", "category": category, "tools": tools}

    return {"status": "ok", "tools_by_category": _registry.get_categories()}


# ---------------------------------------------------------------------------
# Engagement management tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_engagement(name: str, scope_config_path: str = "") -> dict[str, Any]:
    """Create a new pentest engagement session.

    Args:
        name: Human-readable engagement name (e.g. 'HTB-Devvortex').
        scope_config_path: Optional path to scope YAML config file.
    """
    global _current_engagement_id

    if not _engagement:
        return {"status": "error", "message": "Engagement manager not initialised"}

    scope_config = None
    if scope_config_path:
        from pathlib import Path
        import yaml
        path = Path(scope_config_path).resolve()

        # Security: validate scope config path
        if path.suffix.lower() not in (".yaml", ".yml"):
            return {"status": "error", "message": "scope_config_path must be a .yaml or .yml file"}

        home_dir = Path.home().resolve()
        tmp_dir = Path("/tmp").resolve()
        cwd = Path.cwd().resolve()
        if not (
            str(path).startswith(str(home_dir))
            or str(path).startswith(str(tmp_dir))
            or str(path).startswith(str(cwd))
        ):
            return {
                "status": "error",
                "message": "scope_config_path must be within the user's home directory, /tmp, or the current working directory",
            }

        if path.exists():
            scope_config = yaml.safe_load(path.read_text())
    engagement_id = await _engagement.create_engagement(
        name=name,
        scope_config=scope_config,
    )
    _current_engagement_id = engagement_id
    logger.info("engagement created", engagement_id=engagement_id, name=name)
    return {"status": "ok", "engagement_id": engagement_id, "name": name}


@mcp.tool()
async def list_findings(tool: str = "", target: str = "") -> dict[str, Any]:
    """List findings from the current engagement.

    Args:
        tool: Filter by tool name (e.g. 'nmap'). Empty string returns all tools.
        target: Filter by target string. Empty string returns all targets.
    """
    if not _engagement or not _current_engagement_id:
        return {"status": "error", "message": "No active engagement"}

    findings = await _engagement.get_findings(
        engagement_id=_current_engagement_id,
        tool=tool or None,
        target=target or None,
    )
    return {"status": "ok", "engagement_id": _current_engagement_id, "findings": findings}


@mcp.tool()
async def get_engagement_summary() -> dict[str, Any]:
    """Get a full summary of the current engagement including all findings."""
    if not _engagement or not _current_engagement_id:
        return {"status": "error", "message": "No active engagement"}

    engagement = await _engagement.get_engagement(_current_engagement_id)
    findings = await _engagement.get_findings(_current_engagement_id)
    return {
        "status": "ok",
        "engagement": engagement,
        "findings": findings,
        "finding_count": len(findings),
    }


@mcp.tool()
async def export_to_obsidian(vault_path: str = "~/Obsidian/HTB") -> dict[str, Any]:
    """Export current engagement to Obsidian vault as interlinked markdown notes.

    Args:
        vault_path: Path to your Obsidian vault directory (default: ~/Obsidian/HTB).
    """
    if not _engagement or not _current_engagement_id:
        return {"status": "error", "message": "No active engagement"}

    engagement = await _engagement.get_engagement(_current_engagement_id)
    findings = await _engagement.get_findings(_current_engagement_id)

    from astro.reporting.obsidian import ObsidianExporter

    exporter = ObsidianExporter(
        vault_path=vault_path,
        engagement_name=engagement["name"],
    )
    result = exporter.export(findings, engagement_meta=engagement)
    logger.info("obsidian export", vault_path=result["vault_path"], files=result["files_created"])
    return {"status": "ok", **result}


# ---------------------------------------------------------------------------
# MCP Prompts (migrated from V1)
# ---------------------------------------------------------------------------


@mcp.prompt()
async def initial_recon(target_ip: str) -> str:
    """Prompt for initial reconnaissance of a target."""
    return (
        f"Perform initial reconnaissance on {target_ip}. "
        "Start with passive techniques followed by port scanning and service enumeration."
    )


@mcp.prompt()
async def vulnerability_assessment(target_ip: str) -> str:
    """Prompt for vulnerability assessment."""
    return (
        f"Based on the services discovered on {target_ip}, "
        "identify potential vulnerabilities and suggest exploitation techniques."
    )


@mcp.prompt()
async def web_application_testing(target_url: str) -> str:
    """Prompt for web application testing."""
    return (
        f"Analyse the web application at {target_url} for common vulnerabilities "
        "including SQLi, XSS, CSRF, and directory traversal."
    )


# ---------------------------------------------------------------------------
# MCP Resources
# ---------------------------------------------------------------------------


@mcp.resource("astro://engagement/current")
async def current_engagement() -> str:
    """Get current engagement details and findings summary."""
    if not _engagement or not _current_engagement_id:
        return json.dumps({"status": "no_active_engagement"})

    summary = await _engagement.get_summary(_current_engagement_id)
    return json.dumps(summary, default=str, indent=2)


@mcp.resource("astro://scope/config")
async def scope_config() -> str:
    """Get current scope configuration as YAML."""
    if not _scope:
        return "# No scope configuration loaded\n"
    return _scope.to_yaml()


# ---------------------------------------------------------------------------
# Server initialisation
# ---------------------------------------------------------------------------


async def initialize_server(config: "AstroConfig") -> None:  # noqa: F821
    """Initialise server components from a loaded AstroConfig.

    Must be called before the MCP server starts accepting requests.
    """
    from astro.server.batch_endpoints import register_batch_tools
    from astro.server.config import AstroConfig  # local import to avoid circular

    global _executor, _scope, _engagement, _current_engagement_id, _rate_limiter, _auth

    logger.info(
        "initialising server",
        host=config.host,
        port=config.port,
        transport=config.transport,
    )

    _executor = ToolExecutor()

    if config.scope_config_path:
        _scope = ScopeEnforcer(config.scope_config_path)
        logger.info("scope enforcer loaded", path=config.scope_config_path)

    _engagement = EngagementManager(config.db_path)
    await _engagement.initialize()

    _rate_limiter = RateLimiter()
    logger.info("rate limiter initialized")

    _auth = AuthManager(config)
    await _auth.initialize()
    logger.info("auth manager initialized", mode=_auth.auth_mode)

    register_batch_tools(mcp, _run_tool, _registry, _executor)
    logger.info("batch endpoints registered")

    logger.info("server initialisation complete")
