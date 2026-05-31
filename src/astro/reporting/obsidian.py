"""Obsidian vault exporter for engagement findings.

Generates interlinked markdown notes with wikilinks, tags, and
structured frontmatter compatible with Obsidian's graph view.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ObsidianExporter:
    def __init__(self, vault_path: str, engagement_name: str) -> None:
        self._vault = Path(vault_path).expanduser().resolve()

        # Security: ensure vault path is within the user's home directory or /tmp
        home_dir = Path.home().resolve()
        tmp_dir = Path("/tmp").resolve()
        if not (
            str(self._vault).startswith(str(home_dir))
            or str(self._vault).startswith(str(tmp_dir))
        ):
            raise ValueError(
                f"vault_path must be within the user's home directory or /tmp, "
                f"got: {self._vault}"
            )

        self._engagement = engagement_name
        slug = re.sub(r"[^a-zA-Z0-9-]", "-", engagement_name).strip("-")
        slug = slug.replace("..", "")
        self._slug = slug
        self._base = self._vault / self._slug
        self._created_files: list[str] = []

    def export(
        self,
        findings: list[dict[str, Any]],
        engagement_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._base.mkdir(parents=True, exist_ok=True)
        (self._base / "recon").mkdir(exist_ok=True)
        (self._base / "credentials").mkdir(exist_ok=True)
        (self._base / "exploits").mkdir(exist_ok=True)
        (self._base / "loot").mkdir(exist_ok=True)

        hosts = self._extract_hosts(findings)
        creds = self._extract_credentials(findings)
        vulns = self._extract_vulns(findings)

        self._write_index(findings, engagement_meta, hosts, vulns, creds)
        self._write_recon_notes(findings)
        self._write_credential_notes(creds)
        self._write_vuln_notes(vulns)
        self._write_host_notes(hosts, findings)

        return {
            "vault_path": str(self._base),
            "files_created": len(self._created_files),
            "files": self._created_files,
        }

    def _write(self, rel_path: str, content: str) -> None:
        full = self._base / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        self._created_files.append(rel_path)

    def _write_index(
        self,
        findings: list[dict],
        meta: dict | None,
        hosts: dict[str, dict],
        vulns: list[dict],
        creds: list[dict],
    ) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        targets = list(hosts.keys())

        lines = [
            "---",
            f"engagement: {self._engagement}",
            f"date: {now}",
            f"targets: {json.dumps(targets)}",
            f"finding_count: {len(findings)}",
            "tags: [pentest, engagement]",
            "---",
            "",
            f"# {self._engagement}",
            "",
            f"> Exported: {now}  ",
            f"> Findings: {len(findings)} | Hosts: {len(hosts)} | Credentials: {len(creds)} | Vulnerabilities: {len(vulns)}",
            "",
            "## Targets",
            "",
        ]

        for host, info in hosts.items():
            ports_str = ", ".join(str(p) for p in sorted(info.get("ports", [])))
            lines.append(f"- [[{host}]] — {info.get('port_count', 0)} ports ({ports_str})")

        lines += [
            "",
            "## Attack Paths",
            "",
            "```mermaid",
            "graph LR",
        ]

        for i, v in enumerate(vulns[:12]):
            svc = v.get("service", "unknown")
            name = v.get("name", "vuln")[:30]
            lines.append(f"    A[Attacker] --> V{i}[{svc}: {name}]")

        lines += ["```", "", "## Critical Findings", ""]

        for v in vulns:
            sev = v.get("severity", "medium")
            tag = f"#{'critical' if sev == 'critical' else 'high' if sev == 'high' else 'medium'}"
            lines.append(f"- {tag} [[{v.get('name', 'unknown')}]] on [[{v.get('host', '?')}]]:{v.get('port', '?')}")

        lines += ["", "## Credentials Found", ""]
        for c in creds:
            lines.append(f"- `{c['username']}:{c['password']}` — {c.get('source', 'unknown')} {c.get('service', '')}")

        lines += [
            "",
            "## Scan Timeline",
            "",
            "| Time | Tool | Target |",
            "|------|------|--------|",
        ]
        for f in findings:
            t = f.get("created_at", "?")[:19]
            tool = f.get("tool", "?")
            target = f.get("target", "?")
            lines.append(f"| {t} | `{tool}` | {target} |")

        lines += ["", "## Notes", "", ""]

        self._write("_index.md", "\n".join(lines))

    def _write_recon_notes(self, findings: list[dict]) -> None:
        for f in findings:
            tool = f.get("tool", "unknown")
            target = f.get("target", "unknown")
            created = f.get("created_at", "")[:19]
            slug = re.sub(r"[^a-zA-Z0-9-]", "-", f"{tool}-{target}")[:60]

            raw = f.get("raw_output", {})
            parsed = f.get("parsed_output")
            stdout = ""
            if isinstance(raw, dict):
                stdout = raw.get("stdout", "")
            elif isinstance(raw, str):
                stdout = raw

            lines = [
                "---",
                f"tool: {tool}",
                f"target: {target}",
                f"timestamp: {created}",
                f"tags: [recon, {tool}]",
                "---",
                "",
                f"# {tool} — {target}",
                "",
                f"Scanned at: `{created}`",
                "",
            ]

            if parsed and isinstance(parsed, dict):
                hosts = parsed.get("hosts", [])
                for h in hosts:
                    addr = h.get("address", target)
                    lines.append(f"## [[{addr}]]")
                    lines.append("")
                    lines.append("| Port | State | Service | Version |")
                    lines.append("|------|-------|---------|---------|")
                    for p in h.get("ports", []):
                        lines.append(
                            f"| {p.get('port', '?')}/{p.get('protocol', '?')} "
                            f"| {p.get('state', '?')} "
                            f"| {p.get('service', '?')} "
                            f"| {p.get('version', '')} |"
                        )
                    lines.append("")

            lines += [
                "## Raw Output",
                "",
                "```",
                stdout[:5000] if stdout else "(no output)",
                "```",
            ]

            self._write(f"recon/{slug}.md", "\n".join(lines))

    def _write_credential_notes(self, creds: list[dict]) -> None:
        if not creds:
            return

        lines = [
            "---",
            "tags: [credentials, loot]",
            "---",
            "",
            "# Credentials",
            "",
            "| Username | Password | Source | Service | Hash |",
            "|----------|----------|--------|---------|------|",
        ]
        for c in creds:
            lines.append(
                f"| `{c['username']}` | `{c['password']}` "
                f"| {c.get('source', '?')} | {c.get('service', '?')} "
                f"| {c.get('hash', '')} |"
            )

        lines += ["", "## By Service", ""]
        by_svc: dict[str, list[dict]] = {}
        for c in creds:
            svc = c.get("service", "unknown")
            by_svc.setdefault(svc, []).append(c)

        for svc, svc_creds in sorted(by_svc.items()):
            lines.append(f"### {svc}")
            for c in svc_creds:
                lines.append(f"- `{c['username']}:{c['password']}`")
            lines.append("")

        self._write("credentials/all-credentials.md", "\n".join(lines))

    def _write_vuln_notes(self, vulns: list[dict]) -> None:
        for v in vulns:
            name = v.get("name", "unknown")
            slug = re.sub(r"[^a-zA-Z0-9-]", "-", name)[:50]

            lines = [
                "---",
                f"vulnerability: {name}",
                f"severity: {v.get('severity', 'medium')}",
                f"host: {v.get('host', '?')}",
                f"port: {v.get('port', '?')}",
                f"service: {v.get('service', '?')}",
                f"cve: {v.get('cve', '')}",
                f"tags: [vuln, {v.get('severity', 'medium')}]",
                "---",
                "",
                f"# {name}",
                "",
                f"**Severity**: {v.get('severity', 'medium').upper()}  ",
                f"**Host**: [[{v.get('host', '?')}]]  ",
                f"**Port**: {v.get('port', '?')}/{v.get('service', '?')}  ",
                f"**CVE**: {v.get('cve', 'N/A')}  ",
                "",
                "## Description",
                "",
                v.get("description", ""),
                "",
                "## Proof of Concept",
                "",
                f"```\n{v.get('proof', '')}\n```",
                "",
                "## Remediation",
                "",
                v.get("remediation", "Patch or disable the affected service."),
                "",
            ]

            self._write(f"exploits/{slug}.md", "\n".join(lines))

    def _write_host_notes(self, hosts: dict[str, dict], findings: list[dict]) -> None:
        for host, info in hosts.items():
            slug = re.sub(r"[^a-zA-Z0-9.-]", "-", host)
            slug = slug.replace("..", "")

            lines = [
                "---",
                f"host: {host}",
                f"ports: {json.dumps(sorted(info.get('ports', [])))}",
                f"os: {info.get('os', 'unknown')}",
                "tags: [host, target]",
                "---",
                "",
                f"# {host}",
                "",
                f"**OS**: {info.get('os', 'Unknown')}  ",
                f"**Ports**: {info.get('port_count', 0)} open  ",
                "",
                "## Open Ports",
                "",
                "| Port | Service | Version |",
                "|------|---------|---------|",
            ]

            for svc in info.get("services", []):
                lines.append(f"| {svc.get('port', '?')} | {svc.get('service', '?')} | {svc.get('version', '')} |")

            lines += ["", "## Findings", ""]
            for f in findings:
                if f.get("target", "") == host or host in f.get("target", ""):
                    t = f.get("tool", "?")
                    ts = f.get("created_at", "")[:19]
                    lines.append(f"- `{ts}` — [[recon/{t}-{slug}|{t}]]")

            lines.append("")
            self._write(f"{slug}.md", "\n".join(lines))

    def _extract_hosts(self, findings: list[dict]) -> dict[str, dict]:
        hosts: dict[str, dict] = {}
        for f in findings:
            parsed = f.get("parsed_output")
            if not parsed or not isinstance(parsed, dict):
                continue
            for h in parsed.get("hosts", []):
                addr = h.get("address", "")
                if not addr:
                    continue
                if addr not in hosts:
                    hosts[addr] = {"ports": [], "services": [], "os": "Unknown", "port_count": 0}
                for p in h.get("ports", []):
                    port_num = p.get("port", 0)
                    if port_num not in hosts[addr]["ports"]:
                        hosts[addr]["ports"].append(port_num)
                        hosts[addr]["services"].append(p)
                hosts[addr]["port_count"] = len(hosts[addr]["ports"])
                if h.get("os"):
                    hosts[addr]["os"] = h["os"][0] if isinstance(h["os"], list) and h["os"] else str(h["os"])
        return hosts

    def _extract_credentials(self, findings: list[dict]) -> list[dict]:
        creds: list[dict] = []
        seen: set[str] = set()

        for f in findings:
            raw = f.get("raw_output", {})
            stdout = ""
            if isinstance(raw, dict):
                stdout = raw.get("stdout", "")
            elif isinstance(raw, str):
                stdout = raw

            tool = f.get("tool", "")

            if tool == "hydra":
                for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", stdout):
                    key = f"{m.group(1)}:{m.group(2)}"
                    if key not in seen:
                        seen.add(key)
                        creds.append({"username": m.group(1), "password": m.group(2), "source": "hydra", "service": f.get("target", "")})

            if "Valid credentials" in stdout or "valid accounts" in stdout.lower():
                for m in re.finditer(r"(\w+):(\w+)\s*-\s*Valid", stdout):
                    key = f"{m.group(1)}:{m.group(2)}"
                    if key not in seen:
                        seen.add(key)
                        creds.append({"username": m.group(1), "password": m.group(2), "source": tool, "service": ""})

            if "empty password" in stdout.lower():
                key = "root:(empty)"
                if key not in seen:
                    seen.add(key)
                    creds.append({"username": "root", "password": "(empty)", "source": "mysql", "service": "mysql"})

            if "tomcat" in stdout.lower() and "Default account" in stdout:
                key = "tomcat:tomcat"
                if key not in seen:
                    seen.add(key)
                    creds.append({"username": "tomcat", "password": "tomcat", "source": "nikto", "service": "tomcat-manager"})

        return creds

    def _extract_vulns(self, findings: list[dict]) -> list[dict]:
        vulns: list[dict] = []

        for f in findings:
            raw = f.get("raw_output", {})
            stdout = ""
            if isinstance(raw, dict):
                stdout = raw.get("stdout", "")
            elif isinstance(raw, str):
                stdout = raw

            target = f.get("target", "?")
            host = re.sub(r"https?://", "", target).split(":")[0].split("/")[0]

            if "VULNERABLE" in stdout:
                for m in re.finditer(r"(CVE-\d{4}-\d+)", stdout):
                    cve = m.group(1)
                    desc_match = re.search(rf"{cve}.*?(?:Risk factor|State|Disclosure).*?$", stdout, re.M | re.S)
                    vulns.append({
                        "name": cve,
                        "cve": cve,
                        "host": host,
                        "port": self._guess_port(stdout, f),
                        "service": f.get("tool", ""),
                        "severity": "critical",
                        "description": f"Confirmed vulnerable to {cve}",
                        "proof": stdout[:500],
                        "remediation": f"Patch {cve} or disable the affected service.",
                    })

            if "Default account" in stdout:
                vulns.append({
                    "name": "default-credentials",
                    "cve": "",
                    "host": host,
                    "port": self._guess_port(stdout, f),
                    "service": "tomcat",
                    "severity": "high",
                    "description": "Default credentials found for Tomcat Manager",
                    "proof": "tomcat:tomcat",
                    "remediation": "Change default credentials immediately.",
                })

            if "empty password" in stdout.lower() and "root" in stdout.lower():
                vulns.append({
                    "name": "mysql-root-no-password",
                    "cve": "",
                    "host": host,
                    "port": "3306",
                    "service": "mysql",
                    "severity": "critical",
                    "description": "MySQL root account has no password",
                    "proof": "mysql-empty-password NSE script confirmed",
                    "remediation": "Set a strong password for the MySQL root account.",
                })

            if "rmi-vuln-classloader" in stdout and "VULNERABLE" in stdout:
                vulns.append({
                    "name": "java-rmi-classloader-rce",
                    "cve": "",
                    "host": host,
                    "port": "1099",
                    "service": "java-rmi",
                    "severity": "critical",
                    "description": "RMI registry allows loading classes from remote URLs → RCE",
                    "proof": stdout[:300],
                    "remediation": "Restrict RMI registry access or disable remote classloading.",
                })

        return vulns

    @staticmethod
    def _guess_port(stdout: str, finding: dict) -> str:
        m = re.search(r"(\d+)/tcp\s+open", stdout)
        if m:
            return m.group(1)
        target = finding.get("target", "")
        port_match = re.search(r":(\d+)", target)
        if port_match:
            return port_match.group(1)
        return "?"
