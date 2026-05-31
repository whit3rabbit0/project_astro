# Project Astro V2 — HTB Insane Machine Gap Analysis

## Objective

Map the techniques required to solve HackTheBox Insane-level machines against Project Astro V2's current capabilities. Identify gaps and prioritize new tools/features.

---

## Insane Machine Attack Categories

Based on research of retired Insane machines (Rebound, Sizzle, Delegate, Rope, Backfire, Dyplesher, Reddish, Unobtainium, CTF, Sekhmet, Cereal, Time, Carpediem, and others), Insane boxes cluster into these attack categories:

| Category | Frequency | Example Machines |
|----------|-----------|-----------------|
| Active Directory / Kerberos | Very High | Rebound, Sizzle, Delegate, Redelegate, Hercules |
| Web Exploitation + Deserialization | Very High | Cereal, Sekhmet, Time, Perspective, Roundcube |
| Multi-Step Exploitation Chains | High | Backfire (SSRF→C2→JWT), AdmirerToo (SSRF→OpenTSDB) |
| Binary Exploitation / Memory Corruption | Medium | Rope (BOF+format string), Smasher (ROP chains) |
| Container / Kubernetes Escape | Medium | Unobtainium (k8s), Carpediem (cgroups CVE-2022-0492) |
| Unusual Protocols (Redis, AMQP, MQTT) | Medium | Dyplesher (memcache+AMQP), Reddish (Node-RED+Redis), Broker (ActiveMQ) |
| Cryptography / Custom Ciphers | Low-Medium | SPG (AES-ECB), CryptoHorrific (mobile crypto) |
| Race Conditions / Timing | Low | Desire (SHA256 timestamp prediction) |
| Privilege Escalation (Linux) | Always | Kernel exploits, SUID abuse, cgroups escape |
| Privilege Escalation (Windows) | Always | AlwaysInstallElevated, SeImpersonate, UAC bypass, AppLocker bypass |

---

## Gap Analysis: V2 Capabilities vs Insane Requirements

### LEGEND
- COVERED = V2 has this tool/capability
- PARTIAL = V2 has related capability but not the specific tool
- GAP = V2 cannot handle this today

---

### 1. Active Directory / Kerberos Attacks

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Port/service discovery | COVERED | nmap |
| SMB enumeration | COVERED | enum4linux, crackmapexec, smbclient |
| Kerberoasting (GetUserSPNs) | GAP | Impacket suite (GetUserSPNs.py) |
| AS-REP Roasting | GAP | Impacket (GetNPUsers.py) |
| BloodHound data collection | GAP | bloodhound-python / SharpHound |
| BloodHound attack path analysis | GAP | bloodhound-python + neo4j queries |
| Constrained Delegation abuse | GAP | Impacket (getST.py, S4U2Self/S4U2Proxy) |
| Unconstrained Delegation | GAP | Rubeus / Impacket |
| RBCD (Resource-Based Constrained Delegation) | GAP | Impacket (rbcd.py) |
| DCSync | GAP | Impacket (secretsdump.py) |
| Pass-the-Hash / Pass-the-Ticket | PARTIAL | evil-winrm (hash support), but no Impacket |
| Golden/Silver Ticket forging | GAP | Impacket (ticketer.py) |
| DNS manipulation in AD | GAP | Impacket (dnstool.py) |
| ADCS certificate abuse | GAP | Certipy |
| Password spraying | COVERED | crackmapexec |
| WinRM execution | COVERED | evil-winrm |

**Gap severity: CRITICAL** — AD machines dominate Insane tier. Impacket integration is mandatory.

---

### 2. Web Exploitation

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Web scanning | COVERED | nikto, wpscan, whatweb |
| Directory/file fuzzing | COVERED | gobuster, dirb, ffuf |
| SQL injection | COVERED | sqlmap |
| SSRF detection + exploitation | GAP | Burp Suite / custom scripts |
| Deserialization attacks | GAP | ysoserial / custom exploit scripts |
| JWT cracking/forging | GAP | jwt_tool / custom scripts |
| XXE exploitation | GAP | Custom scripts |
| LDAP injection | GAP | Custom scripts |
| XSS exploitation | PARTIAL | Burp (planned), custom_script |
| File upload exploitation | PARTIAL | custom_script |
| IDOR discovery | PARTIAL | Burp (planned) |
| API testing | PARTIAL | ffuf, custom_script |

**Gap severity: HIGH** — Burp integration (planned) covers many. JWT and deserialization need dedicated tools.

---

### 3. Multi-Step Exploitation Chains

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| SSRF → internal service discovery | PARTIAL | custom_script + internal nmap |
| Chained vulnerability exploitation | PARTIAL | custom_script handles arbitrary code |
| Pivoting through compromised host | GAP | chisel / ligolo-ng / SSH tunneling |
| Internal port scanning from foothold | GAP | Need shell session + nmap/portscanner |
| Proxy chains | GAP | proxychains + SOCKS proxy setup |

**Gap severity: HIGH** — Pivoting is the core of multi-step chains. Need tunneling tools.

---

### 4. Shell Management + Post-Exploitation

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Reverse shell listener | GAP | netcat / ncat / socat |
| Payload generation | GAP | msfvenom |
| Web shell deployment | PARTIAL | custom_script |
| Shell session tracking | GAP | shell_manager (new module) |
| Linux privesc enumeration | GAP | linpeas / linenum |
| Windows privesc enumeration | GAP | winpeas / PowerUp |
| File transfer to/from target | GAP | Need upload/download helpers |
| Lateral movement | PARTIAL | crackmapexec, evil-winrm |

**Gap severity: CRITICAL** — Cannot complete any Insane box without shell management.

---

### 5. Binary Exploitation

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Buffer overflow exploitation | GAP | pwntools (Python library) |
| ROP chain generation | GAP | ROPgadget / ropper |
| Format string exploitation | GAP | Custom scripts + pwntools |
| Binary analysis | GAP | radare2 / Ghidra (external) |
| Shellcode generation | GAP | msfvenom / pwntools |

**Gap severity: MEDIUM** — Appears in ~30% of Insane boxes. custom_script + pwntools covers most cases.

---

### 6. Container / Kubernetes Escape

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Docker socket abuse | GAP | docker CLI via custom_script |
| cgroups escape | GAP | Custom exploit scripts |
| Kubernetes RBAC enumeration | GAP | kubectl |
| Pod privilege escalation | GAP | kubectl + custom manifests |
| Service account token abuse | GAP | kubectl + curl |

**Gap severity: MEDIUM** — Appears in ~15% of Insane boxes. custom_script covers most.

---

### 7. Unusual Protocol Exploitation

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Redis exploitation | GAP | redis-cli wrapper |
| Memcache exploitation | GAP | Custom scripts |
| AMQP/MQTT interaction | GAP | Custom scripts |
| ActiveMQ exploitation | GAP | Custom exploit + nmap detection |
| Node-RED exploitation | GAP | Custom scripts (HTTP-based) |
| SNMP enumeration | GAP | snmpwalk wrapper |

**Gap severity: LOW-MEDIUM** — Niche but present. custom_script handles most via CLI tools.

---

### 8. Cryptography

| Technique | V2 Status | Tool Needed |
|-----------|-----------|-------------|
| Hash cracking | COVERED | john, hashcat |
| Custom cipher analysis | PARTIAL | custom_script (Python crypto libs) |
| Key/IV extraction | PARTIAL | custom_script |
| JWT secret cracking | GAP | Dedicated jwt_tool or hashcat rule |

**Gap severity: LOW** — john + hashcat + custom_script covers most.

---

## Priority Tool Additions

### P0: Critical (blocks most Insane boxes)

| Tool | Purpose | Implementation |
|------|---------|----------------|
| **Impacket suite** | AD attacks (Kerberoasting, DCSync, delegation, tickets) | Wrapper tool that calls Impacket Python scripts |
| **msfvenom** | Payload generation for reverse shells | Dedicated tool with structured output |
| **netcat/ncat** | Reverse shell listener | Tool with session tracking |
| **shell_manager** | Track active shell sessions | New core module |
| **linpeas/winpeas** | Privilege escalation enumeration | Tool that executes through active shell |
| **Burp Suite** | Web app scanning + SSRF/deserialization | REST API integration (already planned) |

### P1: High (needed for 50%+ of Insane boxes)

| Tool | Purpose | Implementation |
|------|---------|----------------|
| **bloodhound-python** | AD attack path collection | Dedicated tool |
| **certipy** | ADCS certificate abuse | Dedicated tool |
| **chisel/ligolo** | Pivoting/tunneling | Tool + proxy management |
| **jwt_tool** | JWT cracking and forging | Dedicated tool or hashcat rules |
| **proxychains** | Route tools through pivots | Config management |

### P2: Medium (needed for specific box types)

| Tool | Purpose |
|------|---------|
| **pwntools** | Binary exploitation (Python library, used via custom_script) |
| **redis-cli** | Redis exploitation |
| **snmpwalk** | SNMP enumeration |
| **kubectl** | Kubernetes attacks |
| **kerbrute** | Kerberos username enumeration |

### P3: Low (nice-to-have)

| Tool | Purpose |
|------|---------|
| **ysoserial** | Java deserialization gadget chains |
| **radare2** | Binary analysis |
| **ROPgadget** | ROP chain generation |
| **mqtt-cli** | MQTT protocol testing |

---

## Architecture Impact

### New Core Module: Shell Manager

```
src/astro/core/shell_manager.py

class ShellSession:
    id: str
    target: str
    user: str
    privilege: str  # "user", "root", "SYSTEM"
    shell_type: str  # "reverse", "bind", "web", "winrm"
    status: str  # "active", "dead"
    created_at: datetime

class ShellManager:
    sessions: dict[str, ShellSession]
    
    async def create_listener(port, shell_type) -> ShellSession
    async def execute_in_shell(session_id, command) -> str
    async def upload_file(session_id, local_path, remote_path)
    async def download_file(session_id, remote_path, local_path)
    async def list_sessions() -> list[ShellSession]
```

### New Tool Category: Post-Exploitation

```python
TOOL_CATEGORIES = {
    # ... existing ...
    # New
    "impacket": ToolCategory.EXPLOITATION,
    "msfvenom": ToolCategory.EXPLOITATION,
    "netcat": ToolCategory.EXPLOITATION,
    "bloodhound": ToolCategory.RECON,
    "certipy": ToolCategory.EXPLOITATION,
    "linpeas": ToolCategory.POST_EXPLOITATION,  # New category
    "winpeas": ToolCategory.POST_EXPLOITATION,
    "chisel": ToolCategory.POST_EXPLOITATION,
}
```

### Methodology Tracker Update

Add new PTES phases for post-exploitation:
```python
"post_exploitation": {
    "tools": ["linpeas", "winpeas", "bloodhound", "crackmapexec", 
              "evil-winrm", "smbclient", "chisel", "custom_script"],
}
```

---

## Coverage Summary

| Category | Current Coverage | After P0 Tools | After P0+P1 |
|----------|-----------------|----------------|-------------|
| AD/Kerberos | 20% | 70% | 95% |
| Web Exploitation | 55% | 80% | 90% |
| Multi-Step Chains | 30% | 60% | 85% |
| Shell/Post-Exploitation | 10% | 75% | 90% |
| Binary Exploitation | 5% | 15% | 40% |
| Container/K8s | 5% | 15% | 30% |
| Protocol Exploitation | 10% | 20% | 35% |
| Cryptography | 60% | 65% | 75% |
| **Overall Insane Readiness** | **~25%** | **~55%** | **~75%** |

The remaining 25% requires binary exploitation expertise and niche protocol knowledge that's best handled by custom_script + LLM reasoning, which is already in V2.

---

## Recommended Build Order

1. **Sprint 1**: Impacket suite + msfvenom + netcat + shell_manager (unlocks AD + shell management)
2. **Sprint 2**: Burp integration + linpeas/winpeas + bloodhound-python (unlocks web + post-exploitation)
3. **Sprint 3**: chisel/proxychains + certipy + jwt_tool (unlocks pivoting + ADCS + JWT)
4. **Sprint 4**: Protocol tools (redis, snmp, kubectl) + pwntools integration
