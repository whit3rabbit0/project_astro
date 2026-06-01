# Project Astro V2

Intelligence layer for LLM-driven penetration testing. Ships as an MCP server with 38 Kali tool wrappers, engagement tracking, scope enforcement, and structured output for any MCP-compatible client.

> **This is a devkit.** Use only against targets you own or have explicit authorization to test.

## What changed from V1

V1 was a Flask proxy that shuttled JSON between Claude Desktop and a `kali_api_server.py` process. It worked, but the architecture was fragile — two servers, no state, no safety rails, 10 tools hard-wired to HTTP endpoints.

V2 is a ground-up rewrite:

| | V1 | V2 |
|---|---|---|
| **Architecture** | Flask API + MCP shim (2 processes) | Single FastMCP server (`mcp` SDK) |
| **Transport** | HTTP only | Streamable-HTTP or stdio |
| **Tools** | 10, inline in one file | 38 wrappers (+ custom script executor), each in `src/astro/tools/` |
| **Tool validation** | None — raw strings to shell | Pydantic-based validation, shell metacharacter blocking, blocked-flag list |
| **Scope enforcement** | None | CIDR + domain allowlists via YAML config; every tool call is checked |
| **Rate limiting** | None | Per-tool async semaphores |
| **Auth** | None | API key + OIDC support |
| **Engagement tracking** | None | SQLite-backed finding recorder with per-engagement isolation |
| **Output parsing** | Raw stdout | Structured parsers for nmap, sqlmap, wpscan, nuclei, subfinder, etc. |
| **Reporting** | None | SARIF, HTML, Obsidian vault export, remediation mapping |
| **Intelligence** | None | CVE correlator (NVD API), attack graph builder (NetworkX), methodology tracker |
| **CLI** | `run.py` (starts 2 servers) | `astro serve`, `astro ollama`, `astro tui`, `astro version` |
| **Packaging** | `requirements.txt` + `venv` | `pyproject.toml`, installable via `pip install .` |
| **Container** | None | Multi-stage Kali Linux Dockerfile, docker-compose for lab environments |
| **LLM support** | Claude Desktop only | Any MCP client, plus native Ollama bridge and OpenAI-compatible bridge |
| **Tests** | None | pytest suite (unit + integration), ruff, mypy strict |

### New tools (V2 additions)

Recon: `amass`, `subfinder`, `ffuf`, `whatweb`, `dnsrecon`, `theharvester`, `nuclei`

Exploitation: `searchsploit`, `crackmapexec`, `hashcat`, `responder`, `smbclient`, `evil-winrm`

Impacket suite: `secretsdump`, `psexec`, `wmiexec`, `kerberoast`, `getnpusers`, `getst`, `ticketer`

Post-exploitation: `linpeas`, `winpeas`, `bloodhound`, `chisel`, `netcat`, `msfvenom`

Tunneling/C2: `burp` (proxy integration), `certipy` (AD CS attacks)

Flex: `custom_script` (arbitrary bash/python with timeout + sandbox)

### Removed

- `kali_api_server.py` — no longer needed; tools execute directly
- `run.py` — replaced by `astro` CLI
- `requirements.txt` — replaced by `pyproject.toml`
- `setup.sh` — replaced by `pip install .` or Docker

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

The server starts on `http://localhost:8080` with streamable-HTTP transport. All 38 Kali tools are pre-installed in the image.

### Docker lab (with a target)

```bash
docker compose -f docker-compose.lab.yml up --build
```

Starts Astro + a Metasploitable2 target on an isolated `172.28.0.0/24` network with scope pre-configured.

### Local install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install ".[dev,reporting]"
astro serve --port 8080
```

Requires the underlying Kali tools to be installed on the host.

## Usage

### MCP server (default)

```bash
astro serve --transport streamable-http --port 8080
astro serve --transport stdio  # for Claude Desktop / Claude Code
```

Connect any MCP client to `http://localhost:8080` or wire it up via stdio in your client config:

```json
{
  "mcpServers": {
    "astro": {
      "command": "astro",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

### Ollama bridge (offline / local LLM)

```bash
astro ollama --model llama3 --scope config/lab_scope.yaml
```

Interactive chat session with tool-calling against a local Ollama instance.

### Terminal UI

```bash
astro tui --target 10.10.10.10 --engagement "HTB-Box"
```

Rich terminal interface with live tool output, methodology tracking, and engagement management.

## Scope enforcement

Create a YAML scope file to restrict what targets tools can hit:

```yaml
scope:
  allowed_cidrs:
    - "10.10.10.0/24"
  allowed_domains:
    - "target.htb"
  excluded_targets: []

  tool_restrictions:
    hydra:
      enabled: true
      max_threads: 4
      service_whitelist: ["ssh", "http"]
    sqlmap:
      risk_level: 2
```

```bash
astro serve --scope config/scope.yaml
```

Every tool call validates its target against the scope before execution. Out-of-scope targets are rejected.

## Tools (38)

### Recon

| Tool | Description |
|---|---|
| `nmap` | Network scanner with structured output parsing |
| `gobuster` | Directory/DNS/vhost brute-forcer |
| `dirb` | Web content scanner |
| `nikto` | Web server vulnerability scanner |
| `wpscan` | WordPress vulnerability scanner |
| `enum4linux` | Windows/Samba enumeration |
| `subfinder` | Passive subdomain discovery |
| `amass` | Attack surface mapping |
| `ffuf` | Web fuzzer |
| `whatweb` | Technology fingerprinting |
| `dnsrecon` | DNS reconnaissance |
| `theharvester` | OSINT email/subdomain harvesting |
| `nuclei` | Template-based vulnerability scanner |

### Exploitation

| Tool | Description |
|---|---|
| `sqlmap` | SQL injection tester with DB enumeration |
| `metasploit` | Exploitation framework (msfconsole) |
| `hydra` | Network login brute-forcer |
| `john` | Password cracker |
| `hashcat` | GPU-accelerated password cracker |
| `searchsploit` | Exploit-DB local search |
| `crackmapexec` | Network protocol attack tool |
| `responder` | LLMNR/NBT-NS/mDNS poisoner |
| `smbclient` | SMB client |
| `evil-winrm` | WinRM shell |

### Impacket suite

| Tool | Description |
|---|---|
| `impacket_secretsdump` | SAM/LSA/NTDS credential extraction |
| `impacket_psexec` | Remote command execution via SMB |
| `impacket_wmiexec` | Remote command execution via WMI |
| `impacket_kerberoast` | SPN-based Kerberos ticket extraction |
| `impacket_getnpusers` | AS-REP roasting |
| `impacket_getst` | Service ticket requests |
| `impacket_ticketer` | Silver/golden ticket forging |

### Post-exploitation

| Tool | Description |
|---|---|
| `linpeas` | Linux privilege escalation scanner |
| `winpeas` | Windows privilege escalation scanner |
| `bloodhound` | Active Directory relationship mapper |
| `msfvenom` | Payload generator |
| `netcat` | Network Swiss army knife |
| `chisel` | TCP/UDP tunnel over HTTP |
| `certipy` | AD Certificate Services attacks |
| `burp` | Burp Suite proxy integration |

### Other

| Tool | Description |
|---|---|
| `custom_script` | Run arbitrary bash/python with timeout sandbox |

## Engagement tracking

```
create_engagement("HTB-Devvortex")  →  engagement ID
  └─ nmap_scan(...)                 →  finding recorded
  └─ nikto_scan(...)                →  finding recorded
  └─ sqlmap_scan(...)               →  finding recorded
get_engagement_summary()            →  all findings + metadata
export_to_obsidian("~/Vault/HTB")   →  interlinked markdown notes
```

Findings are persisted in SQLite. Export to SARIF for CI integration or HTML for client reports.

## Project structure

```
src/astro/
├── __main__.py          CLI entry point (serve, ollama, tui, version)
├── core/
│   ├── executor.py      Shell command executor with timeout + sandboxing
│   ├── scope.py         CIDR/domain scope enforcer
│   ├── engagement.py    SQLite-backed engagement + finding manager
│   ├── rate_limiter.py  Per-tool async rate limiting
│   ├── auth.py          API key + OIDC authentication
│   ├── validators.py    Input validation (shell metachar blocking, flag filtering)
│   └── parallel.py      Concurrent tool execution
├── tools/
│   ├── base.py          BaseTool ABC (validate → build_command → execute → parse)
│   ├── registry.py      Tool registry with category filtering
│   ├── nmap.py          ... 38 tool wrappers, one per file
│   └── nuclei.py
├── parsers/             Structured output parsers (nmap XML, sqlmap, wpscan JSON)
├── intel/
│   ├── cve_correlator.py   NVD API CPE→CVE lookup
│   ├── attack_graph.py     NetworkX-based attack path modeling
│   └── methodology.py      Phase tracker (recon → exploit → post-exploit)
├── server/
│   ├── mcp_server.py       FastMCP server (all tool + engagement endpoints)
│   ├── ollama_bridge.py    Native Ollama chat with tool calling
│   ├── openai_bridge.py    OpenAI-compatible API bridge
│   └── config.py           Environment-based config loader
├── reporting/
│   ├── sarif.py            SARIF 2.1.0 export
│   ├── html_report.py      Standalone HTML report generator
│   ├── obsidian.py         Obsidian vault export (interlinked notes)
│   └── remediation.py      CWE → remediation mapping
├── observability/
│   ├── logging.py          structlog-based structured logging
│   └── metrics.py          Execution metrics tracking
└── tui/
    ├── app.py              Textual-based terminal UI
    └── widgets.py          Custom TUI widgets
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ASTRO_HOST` | `127.0.0.1` | Server bind address |
| `ASTRO_PORT` | `8080` | Server listen port |
| `ASTRO_TRANSPORT` | `streamable-http` | MCP transport (`streamable-http` or `stdio`) |
| `ASTRO_DB_PATH` | `~/.astro/engagements.db` | SQLite database path |
| `ASTRO_SCOPE_CONFIG` | — | Path to scope YAML config |
| `ASTRO_DEBUG` | `false` | Enable debug logging |
| `API_KEY` | — | API key for authenticated access |

## Development

```bash
pip install ".[dev]"
pytest                    # run tests
ruff check src/ tests/    # lint
mypy src/                 # type check
```

## License

MIT
