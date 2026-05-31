# Project Astro V2: Design Document

## 1. Executive Summary

Project Astro V2 is an intelligence layer for LLM-driven penetration testing. It bridges Large Language Models (Claude, Ollama, OpenAI-compatible) to Kali Linux security tools through the Model Context Protocol (MCP), transforming raw tool output into structured intelligence.

V1 was a basic shell wrapper that executed tools and returned stdout. V2 is fundamentally different: every tool invocation passes through structured parsing, CVE correlation, scope validation, and engagement persistence layers. The thesis is simple: go deep instead of wide. Rather than wrapping 300 tools returning raw output, Astro focuses on 10 tools done correctly with full intelligence—parsing service versions, correlating CVEs, enforcing scope, and persisting results across LLM sessions.

**Key capabilities:**
- Structured output parsing (Nmap XML, WPScan JSON, SQLMap structured formats)
- CVE correlation via NVD API with CVSS scores and CWE mappings
- Scope enforcement: target validation against YAML config before execution
- Engagement persistence: SQLite-backed session storage for stateful LLM reasoning
- Multi-LLM support: Claude Desktop, Ollama, OpenAI-compatible APIs
- Hardened security: subprocess isolation, input validation, no shell execution

---

## 2. Competitive Landscape

| Project | Tools | Intelligence | Scope Enforcement | Engagement Persistence | Multi-LLM |
|---------|-------|-------------|-------------------|----------------------|-----------|
| **Project Astro V2** | 10 | Structured + CVE correlation | YAML config, pre-execution validation | SQLite engagement DB | Claude, Ollama, OpenAI-compat |
| HexStrike AI | 150+ | Raw stdout parsing | None | Memory only | Claude |
| MCP Security Hub | 300+ | Minimal (Docker isolation) | Container boundary | None | Claude |
| PentestThinkingMCP | 8 | MCTS algorithm | None | None | Claude only |
| pentest-mcp | 25+ | Structured engagement/SoW | Implicit via workflow | SoW tracking | Claude |
| pentestMCP | 15+ | Docker-based isolation | Docker boundary | None | Claude |
| TriV3 MCP-Kali-Server | 20+ | Session management | SSH boundary | Session metadata | Claude |
| PentAGI | 40+ | Multi-agent orchestration | None | Agent state | Multi-provider (research) |

**Astro V2's positioning:** Every other project executes tools and returns raw output. We parse it, correlate it, enforce boundaries, and persist it. Scope enforcement happens before execution, not after. CVE correlation is a first-class feature, not a post-processing step. Engagement persistence enables LLMs to reason across tool runs like a human pentester taking notes.

---

## 3. Architecture

### 3a. Native Kali Deployment (Single Process)

```
LLM Client (Claude Desktop / Ollama / OpenAI-compat)
        |
        | MCP Protocol (Streamable HTTP or STDIO)
        |
  [project_astro MCP Server] ← single Python process
        |
        | subprocess.Popen(shell=False)
        |
  [Kali Linux Tools: nmap, nikto, sqlmap, ...]
```

The MCP server acts as a single process bridge. All tool execution is subprocess-based with `shell=False` to prevent shell injection. Tool output flows through parsers, validators, and correlation engines before returning to the LLM.

### 3b. Docker Deployment

```
LLM Client
        |
        | MCP Protocol (Streamable HTTP)
        |
  [project_astro container] (Python + Kali tools)
        |
        | subprocess execution inside container
        |
  [Kali Linux tools pre-installed in image]
```

Docker deployment isolates tool execution from the host OS. The container image includes all 10 tools plus Python dependencies. MCP server listens on a configurable port, accessible to the host LLM client via HTTP.

### 3c. Internal Module Architecture

Layered design from low-level execution to high-level intelligence:

```
┌─────────────────────────────────────┐
│     Server Layer (MCP Protocol)     │
│  mcp_server.py, bridges (Ollama,    │
│  OpenAI, etc.), transport handlers  │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Core Layer (Execution + Validation)│
│  executor.py, validators.py,        │
│  scope.py, engagement.py, auth.py   │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Tools Layer (Tool Abstraction)     │
│  BaseTool ABC, 10 tool impls,       │
│  ToolRegistry, input schemas        │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Parsers Layer (Output Parsing)     │
│  nmap_parser (libnmap), wpscan,     │
│  sqlmap, nikto, generic_parser      │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Intel Layer (Correlation)          │
│  cve_correlator.py, attack_graph.py,│
│  methodology.py (PTES tracker)      │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Persistence Layer (Storage)        │
│  engagement.py (SQLite), asset DB   │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Reporting Layer (Output Formats)   │
│  sarif.py, html_report.py,          │
│  remediation.py, json_export.py     │
└─────────────────────────────────────┘
```

Each layer is independent and testable. Tools never call Reporting directly; they call Parsers, which feed Intel, which persists via Persistence. The server layer translates MCP/Ollama/OpenAI calls into internal tool invocations.

---

## 4. Key Differentiators

### 4a. Structured Output Parsing

Every tool execution returns both raw stdout and parsed structured data. Parsers are enrichment, not filters.

**Nmap (`-oX` XML):**
- Parse via `python-libnmap` into hosts, ports, services, versions
- Extract CPE strings from OS detection (`osmatch` tags)
- Return structured format: `{hosts: [{ip, ports: [{port, service, version, cpe}]}]}`

**WPScan (`--format json`):**
- Parse JSON into plugins, themes, users, vulnerabilities
- Map plugin vulnerabilities to CVEs
- Return: `{cms: "WordPress", version, plugins: [{name, version, cves: [...]}]}`

**SQLMap (structured output):**
- Parse injection points from `--data` payloads
- Extract databases, tables, columns from successful injections
- Return: `{injectable_params: [...], databases: [...], tables: [...]}`

**Generic fallback:**
- For tools without structured output (hydra, john), parse stdout line-by-line
- Use regex patterns for common formats (user:pass tuples, crack results)
- Always return raw output plus best-effort structured fields

All parsers implement `BaseParser` ABC with `parse(raw_output: str) -> ParsedResult` contract.

### 4b. CVE Correlation Engine

Extract service+version from parsed tool output, correlate with NVD.

**Process:**
1. Parser extracts services: `{service: "Apache HTTP Server", version: "2.4.49"}`
2. Convert to CPE format: `cpe:2.3:a:apache:http_server:2.4.49`
3. Query NVD REST API: `GET /rest/json/cves/1.0?cpeName=cpe:2.3:a:apache:http_server:2.4.49`
4. Return CVEs with CVSS 3.1 scores, CWE IDs, affected version ranges
5. Cache results in SQLite engagement database to avoid re-querying

**Example response:**
```json
{
  "service": "Apache HTTP Server",
  "version": "2.4.49",
  "cpe": "cpe:2.3:a:apache:http_server:2.4.49",
  "cves": [
    {
      "id": "CVE-2021-41773",
      "cvss_v3": 7.5,
      "cwe": "CWE-22",
      "description": "Path traversal in mod_proxy",
      "affected_versions": ["2.4.49"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
    }
  ]
}
```

**No competitor integrates CVE correlation at tool execution time.** Most rely on post-processing or manual CVSS lookup.

### 4c. Scope Enforcement

Target validation happens before subprocess execution, not after. Scope is defined in YAML per engagement.

**YAML structure:**
```yaml
engagement:
  name: "HTB-Devvortex"
  id: "eng-2026-001"
  created_at: "2026-05-30T10:00:00Z"

scope:
  allowed_cidrs:
    - "10.10.10.0/24"
  allowed_domains:
    - "*.htb"
    - "htb.local"
  excluded_targets:
    - "10.10.10.1"  # gateway, exclude from scanning
  
  tool_restrictions:
    hydra:
      max_threads: 4      # reduce noise
      service_whitelist: ["ssh", "http"]  # only these services
    sqlmap:
      db_whitelist: ["webapp"]  # only target this DB
    metasploit:
      payload_whitelist: ["meterpreter/reverse_tcp"]
```

**Validation logic:**
1. Tool invocation arrives with target(s)
2. Load engagement scope from SQLite
3. Validate each target:
   - IP address: match against `allowed_cidrs` using `ipaddress.ip_address().subnet_of()`
   - Domain: match against `allowed_domains` using `fnmatch` globbing
   - Exclusions: reject if in `excluded_targets`
4. Validate tool-specific restrictions (thread counts, whitelists)
5. **Only if validation passes:** execute subprocess
6. Log rejection with clear error message if validation fails

Prevents accidental scanning of production systems during CTF/HTB sessions. Uses Python standard library `ipaddress` and `fnmatch` modules—no external dependencies.

### 4d. Engagement Persistence

SQLite database stores engagement metadata and all tool invocations + parsed results.

**Schema:**
```sql
CREATE TABLE engagements (
  id TEXT PRIMARY KEY,
  name TEXT,
  scope_config TEXT,  -- YAML blob
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE tool_invocations (
  id TEXT PRIMARY KEY,
  engagement_id TEXT,
  tool_name TEXT,
  tool_params JSON,
  raw_output TEXT,
  parsed_output JSON,
  execution_time_ms INT,
  timestamp TIMESTAMP,
  FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE discovered_assets (
  id TEXT PRIMARY KEY,
  engagement_id TEXT,
  asset_type TEXT,  -- 'host', 'service', 'domain', 'user', 'file'
  asset_data JSON,  -- IP, port, service name, version, etc.
  source_tool TEXT,
  timestamp TIMESTAMP,
  FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE cve_cache (
  cpe TEXT PRIMARY KEY,
  cves JSON,
  fetched_at TIMESTAMP,
  expires_at TIMESTAMP
);
```

**Cross-reference queries LLM can request:**
- "Which hosts have port 445 open?"
- "Show all CVEs with CVSS > 7.0"
- "Which WordPress plugins are vulnerable?"
- "What user accounts have been discovered?"

**Enables stateful LLM reasoning:** LLM runs nmap, gets hosts, queries engagement DB, discovers related CVEs from prior tool runs, formulates next action. No need to re-run tools or manually piece together results.

---

## 5. Multi-LLM Support

### Claude Desktop (Official MCP)

Uses the official Anthropic MCP Python SDK.

**Implementation:**
```python
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("project-astro")

@server.call_tool()
async def run_nmap(target: str, scan_type: str = "-sV") -> list[TextContent]:
    # Validation, execution, parsing
    return [TextContent(type="text", text=json.dumps(parsed_result))]
```

**Transport options:**
- Streamable HTTP: Server listens on `localhost:8080`, Claude Desktop connects via HTTP
- STDIO: Server communicates with Claude Desktop via stdin/stdout (for CLI apps)

### Ollama (Native Function Calling)

Ollama 0.4+ supports native function calling with structured `tool_calls` responses.

**Implementation:**
```python
# Request
{
  "model": "mistral",
  "messages": [...],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "nmap",
        "parameters": {
          "type": "object",
          "properties": {
            "target": {"type": "string"},
            "scan_type": {"type": "string"}
          }
        }
      }
    }
  ]
}

# Response
{
  "tool_calls": [
    {
      "id": "call_001",
      "type": "function",
      "function": {
        "name": "nmap",
        "arguments": {"target": "10.10.10.10", "scan_type": "-sV"}
      }
    }
  ]
}
```

Astro maps Ollama `tool_calls` to internal tool execution, returning results back in Ollama format.

### OpenAI-Compatible APIs

OpenAI functions + GPT-4, Mistral API, local vLLM instances.

**Implementation:**
```python
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    base_url="https://api.openai.com/v1"  # or local vLLM endpoint
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "nmap",
            "parameters": {...}
        }
    }
]

response = client.chat.completions.create(
    model="gpt-4",
    messages=[...],
    tools=tools
)
```

Astro adapts OpenAI function-calling format to internal calls. Supports GPT-4, Mistral API, and any OpenAI-compatible endpoint (vLLM, LM Studio, Ollama OpenAI mode).

---

## 6. Tool Catalog

| Tool | Purpose | Key Parameters | Parser | Output Format |
|------|---------|-----------------|--------|----------------|
| **nmap** | Network scanning, service discovery | target, scan_type (-sV/-sA), ports, timing (-T4) | python-libnmap XML parser | Hosts, ports, services, versions, OS detection |
| **gobuster** | Directory/file brute forcing | url, mode (dir/dns/vhost), wordlist, extensions | Regex line-by-line | URLs, status codes, sizes |
| **dirb** | Web content scanner | url, wordlist, output format | Regex line-by-line | Directories, status codes |
| **nikto** | Web server scanner | target, tuning flags (-Tuning) | Regex or JSON | Vulnerabilities, ciphers, headers |
| **sqlmap** | SQL injection detection | url, data, dbs, tables, columns | Structured output parsing | Injection points, database schema |
| **metasploit** | Exploitation framework | module, options (RHOSTS, PAYLOAD) | Tempfile parsing (rc script output) | Exploitation results, shells |
| **hydra** | Credential brute forcing | target, service, username/password lists | Regex (user:pass tuples) | Valid credentials |
| **john** | Password cracking | hash_file, wordlist, format | Regex (hash:password pairs) | Cracked passwords |
| **wpscan** | WordPress vulnerability scanner | url, enumerate flags | JSON parser | WP version, plugins, themes, users, CVEs |
| **enum4linux** | Windows/Samba enumeration | target, all-in-one (-a) | Regex line-by-line | Shares, users, groups, policies |

All tools implement `BaseTool` ABC. Tool registry loads tools dynamically via Python's `importlib`.

---

## 7. Security Model

**Hardening from V1 (preserved):**
- `subprocess.Popen(..., shell=False)` — no shell execution
- Input validation: `validate_url()`, `validate_path()`, `validate_additional_args()`
- `SHELL_METACHARACTERS` regex to block shell injection attempts
- `validate_no_control_chars()` to reject null bytes, newlines in untrusted input
- Metasploit: `tempfile.mkstemp()` for resource scripts (not world-writable /tmp)
- Option value sanitization: reject values containing shell metacharacters

**New in V2:**
- Scope enforcement: target validation before execution (not after)
- API key authentication: environment variable `API_KEY` with SHA-256 hashing
- Localhost binding by default (configurable via `--bind` flag)
- All tool parameters validated against Pydantic schemas (type checking, length limits)
- Subprocess communication: capture both stdout and stderr, log all output
- Rate limiting: configurable per-tool (prevent resource exhaustion)
- Session isolation: each engagement ID maps to separate SQLite DB file

**Defense in depth:**
1. Input arrives at MCP server
2. Pydantic validation (type, length, format)
3. Scope enforcement (CIDR/domain matching)
4. Tool-specific restrictions (thread counts, whitelists)
5. Subprocess execution with timeout
6. Output parsing and sanitization
7. Storage in SQLite with engagement isolation

---

## 8. Scope Configuration Reference

**Engagement scope is YAML-based, stored in SQLite for persistence:**

```yaml
engagement:
  name: "HTB-Machine-Devvortex"
  id: "eng-2026-001"
  created_at: "2026-05-30T10:00:00Z"
  description: "Penetration test of Devvortex HTB machine"
  pentester: "security-team"

scope:
  allowed_cidrs:
    - "10.10.10.0/24"        # HTB subnet
  
  allowed_domains:
    - "*.htb"
    - "htb.local"
  
  excluded_targets:
    - "10.10.10.1"           # Gateway, skip
    - "10.10.10.255"         # Broadcast
  
  tool_restrictions:
    nmap:
      enabled: true
      max_concurrent_scans: 2
      timing_template: "T3"   # Avoid aggressive timing
    
    hydra:
      enabled: true
      max_threads: 4
      service_whitelist:
        - "ssh"
        - "http"
        - "ftp"
    
    sqlmap:
      enabled: true
      db_whitelist:
        - "webapp"
      risk_level: 2
    
    metasploit:
      enabled: true
      payload_whitelist:
        - "meterpreter/reverse_tcp"
        - "meterpreter/reverse_https"

  output_restrictions:
    max_file_size_mb: 100
    max_results_per_tool: 10000

reporting:
  format: "sarif"           # SARIF (Static Analysis Results Format)
  include_remediation: true
```

**CLI to manage engagements:**
```bash
astro engagement create --name "HTB-Devvortex" --scope scope.yaml
astro engagement list
astro engagement show eng-2026-001
astro engagement update eng-2026-001 --scope scope.yaml
```

---

## 9. Deployment Guide

### Native Kali Install

**Prerequisites:**
- Kali Linux (or any Linux with security tools installed)
- Python 3.10+
- All 10 tools installed: `sudo apt install nmap gobuster dirb nikto sqlmap metasploit-framework hydra john wpscan enum4linux`

**Installation:**
```bash
git clone https://github.com/yourusername/project_astro.git
cd project_astro
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Start server (Streamable HTTP transport):**
```bash
astro serve --transport streamable-http --port 8080 --bind localhost
```

**Or STDIO transport (for Claude Desktop integration):**
```bash
astro serve --transport stdio
```

### Docker Deployment

**Docker image includes Kali tools + Python dependencies:**

```bash
docker build -t project-astro:latest .
docker-compose up -d
```

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  astro:
    image: project-astro:latest
    ports:
      - "8080:8080"
    environment:
      - API_KEY=your-api-key-here
      - LOG_LEVEL=info
    volumes:
      - ./engagements:/app/engagements  # Persist SQLite DBs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### Claude Desktop Configuration

**Edit `~/.config/Claude/claude_desktop_config.json`:**

```json
{
  "mcpServers": {
    "project-astro": {
      "url": "http://localhost:8080",
      "description": "Kali Linux tools with CVE correlation and scope enforcement"
    }
  }
}
```

**Restart Claude Desktop** → Project Astro tools appear in tool selector.

### Ollama Integration

**Start Ollama with function calling:**
```bash
ollama pull mistral:latest
ollama serve
```

**Connect Astro to Ollama (in Claude Code or external app):**
```python
from astro.server.ollama_bridge import OllamaAdapter

adapter = OllamaAdapter(base_url="http://localhost:11434")
# Ollama client sends requests to Astro via MCP protocol
```

### OpenAI-Compatible Setup

**Example: OpenAI API**
```bash
export OPENAI_API_KEY="sk-..."
astro serve --llm openai --model gpt-4
```

**Example: Local vLLM**
```bash
vllm serve mistral-7b-instruct-v0.2
astro serve --llm openai --base-url http://localhost:8000/v1
```

---

## 10. Roadmap

### Phase 1: Foundation (Weeks 1-4)
- MCP SDK integration with Streamable HTTP + STDIO transports
- Tool abstraction layer: BaseTool ABC, 10 tool implementations
- Nmap parser (python-libnmap) + XML output validation
- Scope enforcement: YAML config, CIDR/domain validation, pre-execution checks
- Engagement persistence: SQLite schema, CRUD operations
- Multi-LLM bridges: Claude, Ollama, OpenAI-compatible adapters
- Input validation: Pydantic schemas for all tools

### Phase 2: Intelligence (Weeks 5-8)
- CVE correlation engine: CPE conversion, NVD API integration, caching
- WPScan JSON parser + vulnerability mapping
- SQLMap structured output parser
- Attack graph generation (NetworkX): host→service→CVE relationships
- PTES methodology tracker: align discovered assets to PTES phases
- SARIF report generation: OASIS-compliant vulnerability format
- Remediation engine: suggest patches/mitigations per CVE

### Phase 3: Production (Weeks 9-12)
- Docker image + docker-compose (hardened base image, minimal attack surface)
- HTML report generation with charts, timelines, asset inventory
- Rate limiting per tool (prevent resource exhaustion)
- OIDC authentication (for team environments)
- Additional tools: ffuf, feroxbuster, testssl.sh, massdns
- Async execution: run multiple tools in parallel, stream results
- Engagement cloning: template-based scope creation
- Batch tool execution: run multiple nmap scans, aggregate results

---

## 11. Dependencies

All dependencies and their purpose:

| Package | Version | Purpose |
|---------|---------|---------|
| `mcp` | >=1.7.1 | Official Model Context Protocol SDK for tool integration |
| `python-libnmap` | >=0.7.3 | Parse Nmap XML output into structured objects |
| `pydantic` | >=2.0 | Input validation, tool parameter schemas, type safety |
| `structlog` | >=24.0 | Structured logging with context (JSON output for parsing) |
| `pyyaml` | >=6.0 | YAML scope config parsing and serialization |
| `ollama` | >=0.4.8 | Ollama client for function calling integration |
| `aiosqlite` | >=0.20.0 | Async SQLite for engagement persistence (non-blocking DB I/O) |
| `click` | >=8.0 | CLI framework for `astro` command (serve, engagement, etc.) |
| `uvicorn` | >=0.30.0 | ASGI server for Streamable HTTP MCP transport |
| `httpx` | >=0.27.0 | Async HTTP client for NVD API queries, LLM APIs |
| `psutil` | >=6.1.1 | Process monitoring (subprocess health checks, resource limits) |
| `openai` | >=1.0 | OpenAI-compatible API client for function calling |
| `networkx` | >=3.0 | Attack graph generation, vulnerability correlation |

**Dev dependencies** (optional, dev install only):
```
pytest>=8.0
pytest-asyncio>=0.23
ruff>=0.4
mypy>=1.10
```

**Optional extras** (for reporting):
```
jinja2>=3.1  # HTML report generation
```

---

## 12. Testing Strategy

### Unit Tests
- Tool parameter validation (Pydantic schemas)
- Parser output correctness (mock nmap XML, WPScan JSON, etc.)
- Scope validation logic (CIDR matching, domain globbing)
- CVE correlation (CPE conversion, NVD format)

### Integration Tests
- Full tool execution (requires Kali tools installed)
- Engagement create/read/update/delete
- Multi-LLM bridge function-calling format translation
- Parser → intel → persistence pipeline

### End-to-End Tests
- Nmap scan → parse → correlate CVEs → store in engagement DB
- Scope enforcement: reject out-of-scope targets, accept in-scope
- Ollama/OpenAI function calling round-trip

### Security Tests
- Shell injection attempts (blocked by validation)
- Path traversal in file paths
- SQL injection in SQLite queries (parameterized)
- Scope bypass attempts (wrong CIDR, excluded target override)

---

## 13. Future Enhancements

- **Lateral movement tracking**: build attack chains from initial access to high-value assets
- **Stealth scoring**: estimate tool fingerprinting impact (nmap timing, IDS evasion)
- **Compliance mapping**: map discovered vulnerabilities to OWASP Top 10, CIS benchmarks
- **Custom wordlists**: user-provided fuzzing lists per engagement
- **Webhook integration**: notify on critical CVE discovery (CVSS > 9.0)
- **Team collaboration**: real-time engagement sharing, asset conflict resolution
- **Machine learning**: predict asset types (web, database, SSH) from port/service signatures

---

## Summary

Project Astro V2 redefines what an MCP server for penetration testing should be. Rather than mimicking a shell wrapper, it's an intelligence platform: every tool execution is scoped, parsed, correlated, and persisted. The result is an LLM that reasons not from raw nmap output, but from structured intelligence—hosts, services, CVEs, dependencies, and methodology phases all interconnected in a queryable database.

By focusing on 10 tools done deeply instead of 300 tools done shallowly, Astro becomes a force multiplier for skilled penetration testers: they describe the target, Astro handles execution, parsing, correlation, and persistence. The LLM becomes a pair of eyes that never forgets, never misses a CVE, and always respects scope boundaries.
