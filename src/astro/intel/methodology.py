"""PTES methodology tracker."""
from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Static PTES phase definitions
# ---------------------------------------------------------------------------

PTES_PHASES: dict[str, dict[str, Any]] = {
    "pre_engagement": {
        "name": "Pre-engagement Interactions",
        "description": "Define scope, rules of engagement, and objectives",
        "tools": [],
    },
    "intelligence_gathering": {
        "name": "Intelligence Gathering",
        "description": "Passive and active reconnaissance",
        "tools": ["nmap", "enum4linux", "wpscan", "subfinder", "amass", "whatweb", "dnsrecon", "theharvester", "ffuf"],
    },
    "threat_modeling": {
        "name": "Threat Modeling",
        "description": "Identify threats and attack vectors",
        "tools": [],
    },
    "vulnerability_analysis": {
        "name": "Vulnerability Analysis",
        "description": "Discover and validate vulnerabilities",
        "tools": ["nikto", "sqlmap", "wpscan", "nmap", "searchsploit"],
    },
    "exploitation": {
        "name": "Exploitation",
        "description": "Attempt to exploit discovered vulnerabilities",
        "tools": ["metasploit", "sqlmap", "hydra", "crackmapexec", "evil-winrm", "responder", "smbclient", "custom_script"],
    },
    "post_exploitation": {
        "name": "Post Exploitation",
        "description": "Determine value of compromised system and maintain access",
        "tools": ["metasploit", "crackmapexec", "evil-winrm", "smbclient", "custom_script", "hashcat", "john"],
    },
    "reporting": {
        "name": "Reporting",
        "description": "Document findings and recommendations",
        "tools": [],
    },
}

# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


class MethodologyTracker:
    """Tracks PTES methodology phase completion for an engagement."""

    def __init__(self) -> None:
        self.phases: dict[str, dict[str, Any]] = {}
        for phase_id, phase_info in PTES_PHASES.items():
            self.phases[phase_id] = {
                **phase_info,
                "status": "not_started",
                "findings_count": 0,
                "tools_used": [],
                "started_at": None,
                "completed_at": None,
            }

    def record_tool_usage(self, tool_name: str) -> list[str]:
        """Record that a tool was used and update relevant phases.

        Returns a list of phase IDs that were affected.
        """
        affected: list[str] = []
        for phase_id, phase in self.phases.items():
            if tool_name in phase["tools"] and tool_name not in phase["tools_used"]:
                phase["tools_used"].append(tool_name)
                if phase["status"] == "not_started":
                    phase["status"] = "in_progress"
                    phase["started_at"] = datetime.now().isoformat()
                affected.append(phase_id)
                logger.info(
                    "phase_tool_recorded",
                    phase=phase_id,
                    tool=tool_name,
                    status=phase["status"],
                )
        return affected

    def complete_phase(self, phase_id: str) -> None:
        """Mark a phase as completed."""
        if phase_id in self.phases:
            self.phases[phase_id]["status"] = "completed"
            self.phases[phase_id]["completed_at"] = datetime.now().isoformat()
            logger.info("phase_completed", phase=phase_id)

    def increment_findings(self, phase_id: str, count: int = 1) -> None:
        """Increment the findings counter for a phase."""
        if phase_id in self.phases:
            self.phases[phase_id]["findings_count"] += count

    def get_coverage(self) -> dict[str, Any]:
        """Return a methodology coverage summary."""
        total = len(self.phases)
        completed = sum(1 for p in self.phases.values() if p["status"] == "completed")
        in_progress = sum(1 for p in self.phases.values() if p["status"] == "in_progress")
        return {
            "total_phases": total,
            "completed": completed,
            "in_progress": in_progress,
            "not_started": total - completed - in_progress,
            "coverage_percent": round(completed / total * 100, 1),
            "phases": {
                pid: {
                    "status": p["status"],
                    "tools_used": p["tools_used"],
                    "findings_count": p["findings_count"],
                }
                for pid, p in self.phases.items()
            },
        }

    def suggest_next_steps(self) -> list[dict[str, Any]]:
        """Suggest next steps based on methodology gaps.

        Returns suggestions ordered by phase definition order, covering both
        not-started phases with associated tools and in-progress phases with
        remaining tools.
        """
        suggestions: list[dict[str, Any]] = []
        for phase_id, phase in self.phases.items():
            remaining_tools = [
                t for t in phase["tools"] if t not in phase["tools_used"]
            ]
            if phase["status"] == "not_started" and remaining_tools:
                suggestions.append(
                    {
                        "phase": phase["name"],
                        "phase_id": phase_id,
                        "suggestion": (
                            f"Start {phase['name'].lower()} using: "
                            f"{', '.join(remaining_tools)}"
                        ),
                        "tools": remaining_tools,
                    }
                )
            elif phase["status"] == "in_progress" and remaining_tools:
                suggestions.append(
                    {
                        "phase": phase["name"],
                        "phase_id": phase_id,
                        "suggestion": (
                            f"Continue {phase['name'].lower()} — still need: "
                            f"{', '.join(remaining_tools)}"
                        ),
                        "tools": remaining_tools,
                    }
                )
        return suggestions
