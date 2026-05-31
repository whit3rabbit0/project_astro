"""Project Astro TUI — main Textual application."""
from __future__ import annotations

import json
import os
from typing import Any

from rich.panel import Panel
from rich.syntax import Syntax
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, ProgressBar, RichLog, Static, Tree

from astro.tui.widgets import ToolParameterModal


class AstroApp(App):
    """3-panel interactive TUI for Project Astro."""

    CSS = """
    #sidebar {
        width: 22;
        dock: left;
        background: $surface;
        border-right: solid $primary;
    }
    .title {
        background: $primary;
        color: $text;
        text-align: center;
        padding: 0 1;
        text-style: bold;
    }
    #main-content {
        width: 1fr;
    }
    #output-panel {
        height: 2fr;
        border-bottom: solid $primary;
    }
    #status-panel {
        height: 1fr;
    }
    #input-container {
        dock: bottom;
        height: 3;
        background: $surface;
        border-top: solid $primary;
    }
    #command-input {
        height: 3;
    }
    #ptes-progress {
        margin: 1 2;
    }
    #status-text {
        margin: 0 2;
        color: $text-muted;
    }
    """

    TITLE = "Project Astro"
    SUB_TITLE = "v2.0.0"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "run_tool", "Run"),
        Binding("f", "show_findings", "Findings"),
        Binding("e", "export_report", "Export SARIF"),
        Binding("c", "clear_output", "Clear"),
        Binding("s", "show_scope", "Scope"),
        Binding("m", "show_methodology", "PTES"),
        Binding("t", "focus_target", "Set Target"),
        Binding("slash", "show_help", "Help"),
    ]

    def __init__(
        self,
        executor: Any,
        registry: Any,
        scope: Any = None,
        engagement: Any = None,
        methodology: Any = None,
    ) -> None:
        super().__init__()
        self.executor = executor
        self.registry = registry
        self.scope = scope
        self.engagement = engagement
        self.methodology = methodology

        self.current_target: str = ""
        self.current_engagement_id: str | None = None
        self.findings_count: int = 0
        self._selected_tool: str | None = None
        self._awaiting_target: bool = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal():
            # Left sidebar: tool tree
            with Vertical(id="sidebar"):
                yield Static("TOOLKIT", classes="title")
                tree: Tree[str] = Tree("Tools", id="tool-tree")
                tree.root.expand()

                for category, tools in self.registry.get_categories().items():
                    branch = tree.root.add(category.upper(), expand=True)
                    for tool_name in sorted(tools):
                        # data=tool_name ensures node.data is set for selection
                        branch.add_leaf(tool_name, data=tool_name)

                yield tree

            # Right side: output + status stacked vertically
            with Vertical(id="main-content"):
                with Vertical(id="output-panel"):
                    yield Static("OUTPUT", classes="title")
                    yield RichLog(
                        id="output-log",
                        highlight=True,
                        markup=True,
                        wrap=True,
                    )

                with Vertical(id="status-panel"):
                    yield Static("STATUS / FINDINGS", classes="title")
                    yield ProgressBar(
                        id="ptes-progress",
                        total=7,
                        show_eta=False,
                    )
                    yield Static("", id="status-text")
                    yield RichLog(
                        id="findings-log",
                        highlight=True,
                        markup=True,
                        max_lines=50,
                    )

        # Input bar docked to the bottom
        with Vertical(id="input-container"):
            yield Input(
                placeholder="Enter target IP/URL or /command...",
                id="command-input",
            )

        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Populate initial status line after layout is ready."""
        self._update_status()

    # ------------------------------------------------------------------
    # Tree interaction
    # ------------------------------------------------------------------

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Select a tool by clicking its leaf in the sidebar."""
        node = event.node
        # Branch nodes have no data; leaves have data=tool_name
        if not node.data:
            return

        tool_name: str = node.data
        try:
            tool = self.registry.get(tool_name)
        except KeyError:
            return

        self._selected_tool = tool_name
        output = self.query_one("#output-log", RichLog)
        output.write(
            Panel(
                f"Selected: [bold cyan]{tool_name}[/bold cyan]\n"
                f"[dim]{tool.description}[/dim]\n\n"
                "Press [bold]t[/bold] to set target, then [bold]r[/bold] to run.\n"
                "Press [bold]r[/bold] now to open parameter dialog.",
                title=f"[bold]{tool_name}[/bold]",
            )
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def action_run_tool(self) -> None:
        """Open the parameter modal then execute the selected tool."""
        if not self._selected_tool:
            self.notify("Select a tool from the sidebar first", severity="warning")
            return
        if not self.current_target:
            self.notify("Set a target first — press 't'", severity="warning")
            return

        tool_name = self._selected_tool
        default_params = self._build_default_params(tool_name)

        # Push modal to let user adjust params
        params = await self.push_screen_wait(
            ToolParameterModal(tool_name, default_params)
        )
        if params is None:
            # User cancelled
            return

        await self._execute_tool(tool_name, params)

    async def action_focus_target(self) -> None:
        """Focus the input bar for target entry."""
        inp = self.query_one("#command-input", Input)
        inp.placeholder = "Enter target IP / URL..."
        inp.value = ""
        self._awaiting_target = True
        inp.focus()

    async def action_show_findings(self) -> None:
        await self._handle_command("/findings")

    async def action_export_report(self) -> None:
        await self._handle_command("/export")

    async def action_clear_output(self) -> None:
        self.query_one("#output-log", RichLog).clear()

    async def action_show_scope(self) -> None:
        await self._handle_command("/scope")

    async def action_show_methodology(self) -> None:
        await self._handle_command("/ptes")

    async def action_show_help(self) -> None:
        await self._handle_command("/help")

    # ------------------------------------------------------------------
    # Input submission
    # ------------------------------------------------------------------

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        inp = self.query_one("#command-input", Input)
        inp.value = ""

        if not value:
            return

        if self._awaiting_target:
            self._awaiting_target = False
            inp.placeholder = "Enter target IP/URL or /command..."
            self.current_target = value
            self.query_one("#output-log", RichLog).write(
                f"[bold cyan]Target set:[/bold cyan] {value}"
            )
            self._update_status()
            self.notify(f"Target: {value}")
            return

        if value.startswith("/"):
            await self._handle_command(value)
        else:
            # Bare text without a leading slash — treat as target
            self.current_target = value
            self.query_one("#output-log", RichLog).write(
                f"[bold cyan]Target set:[/bold cyan] {value}"
            )
            self._update_status()

    # ------------------------------------------------------------------
    # Command dispatcher
    # ------------------------------------------------------------------

    async def _handle_command(self, cmd: str) -> None:
        output = self.query_one("#output-log", RichLog)
        parts = cmd.split()
        command = parts[0].lower()

        if command == "/engage":
            name = " ".join(parts[1:]) if len(parts) > 1 else "default"
            if self.engagement:
                self.current_engagement_id = await self.engagement.create_engagement(name)
                self.sub_title = f"v2.0.0  |  engagement: {name}"
                output.write(
                    f"[bold green]Engagement created:[/bold green] {name} "
                    f"([dim]{self.current_engagement_id[:8]}...[/dim])"
                )
            else:
                output.write("[yellow]No EngagementManager configured[/yellow]")

        elif command == "/findings":
            if self.engagement and self.current_engagement_id:
                findings = await self.engagement.get_findings(self.current_engagement_id)
                output.write(
                    Panel(
                        Syntax(
                            json.dumps(findings, indent=2, default=str),
                            "json",
                            theme="monokai",
                        ),
                        title="Engagement Findings",
                    )
                )
            else:
                output.write("[yellow]No active engagement. Use /engage <name>[/yellow]")

        elif command == "/export":
            if self.engagement and self.current_engagement_id:
                findings = await self.engagement.get_findings(self.current_engagement_id)
                from astro.reporting.sarif import SARIFGenerator
                sarif = SARIFGenerator()
                report_json = sarif.to_json(findings)
                report_dir = os.path.expanduser("~/.astro")
                os.makedirs(report_dir, exist_ok=True)
                report_path = os.path.join(
                    report_dir,
                    f"report_{self.current_engagement_id[:8]}.sarif.json",
                )
                with open(report_path, "w") as fh:
                    fh.write(report_json)
                output.write(
                    f"[bold green]SARIF report exported:[/bold green] {report_path}"
                )
            else:
                output.write("[yellow]No active engagement to export[/yellow]")

        elif command == "/scope":
            if self.scope:
                import yaml
                # _config is the internal dict; expose it safely
                cfg = getattr(self.scope, "_config", {})
                if cfg:
                    output.write(
                        Panel(
                            yaml.dump(cfg, default_flow_style=False),
                            title="Scope Configuration",
                        )
                    )
                else:
                    output.write("[yellow]Scope enforcer is present but empty (permissive)[/yellow]")
            else:
                output.write("[yellow]No scope configured — all targets permitted[/yellow]")

        elif command == "/ptes":
            if self.methodology:
                coverage = self.methodology.get_coverage()
                suggestions = self.methodology.suggest_next_steps()
                output.write(
                    Panel(
                        Syntax(
                            json.dumps(
                                {"coverage": coverage, "next_steps": suggestions},
                                indent=2,
                            ),
                            "json",
                            theme="monokai",
                        ),
                        title="PTES Methodology Status",
                    )
                )
            else:
                output.write("[yellow]No MethodologyTracker configured[/yellow]")

        elif command == "/help":
            output.write(
                Panel(
                    "[bold]Commands[/bold]\n"
                    "  /engage [name]  — Create / name an engagement\n"
                    "  /findings       — Show all findings for current engagement\n"
                    "  /export         — Export SARIF report to ~/.astro/\n"
                    "  /scope          — Show active scope configuration\n"
                    "  /ptes           — PTES methodology coverage and next steps\n"
                    "  /help           — Show this help\n\n"
                    "[bold]Keybindings[/bold]\n"
                    "  t  Set target     r  Run selected tool\n"
                    "  f  Findings       e  Export SARIF\n"
                    "  s  Scope          m  PTES status\n"
                    "  c  Clear output   q  Quit\n"
                    "  /  Help",
                    title="Help",
                )
            )

        else:
            output.write(f"[red]Unknown command: [bold]{command}[/bold] — type /help[/red]")

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_name: str, params: dict) -> None:
        output = self.query_one("#output-log", RichLog)
        findings_log = self.query_one("#findings-log", RichLog)

        output.write(
            f"\n[bold green]▶ Running [cyan]{tool_name}[/cyan] "
            f"against [yellow]{self.current_target}[/yellow]...[/bold green]"
        )

        # Scope check
        if self.scope:
            try:
                self.scope.validate_target(self.current_target)
            except Exception as exc:
                output.write(f"[bold red]SCOPE VIOLATION: {exc}[/bold red]")
                self.notify(f"Scope violation: {exc}", severity="error")
                return

        try:
            tool = self.registry.get(tool_name)
            result = await tool.execute(self.executor, params)
        except Exception as exc:
            output.write(f"[bold red]Error executing {tool_name}: {exc}[/bold red]")
            self.notify(f"Error: {exc}", severity="error")
            return

        # Render raw stdout / stderr
        stdout: str = result.raw.get("stdout", "")
        stderr: str = result.raw.get("stderr", "")
        if stdout:
            output.write(
                Panel(
                    Syntax(stdout, "text", theme="monokai", line_numbers=False),
                    title=f"{tool_name} — stdout",
                )
            )
        if stderr:
            output.write(f"[yellow]{stderr}[/yellow]")

        # Render structured parsed output when available
        if result.parsed:
            output.write(
                Panel(
                    Syntax(
                        json.dumps(result.parsed, indent=2, default=str),
                        "json",
                        theme="monokai",
                    ),
                    title=f"{tool_name} — Structured Output",
                )
            )

        # Update findings log
        self.findings_count += 1
        status_icon = "[green]✓[/green]" if result.success else "[red]✗[/red]"
        summary = self._summarize_result(result)
        findings_log.write(
            f"{status_icon} [cyan]{tool_name}[/cyan] → "
            f"[yellow]{self.current_target}[/yellow]: {summary}"
        )

        # Update PTES methodology
        if self.methodology:
            self.methodology.record_tool_usage(tool_name)
            coverage = self.methodology.get_coverage()
            progress = self.query_one("#ptes-progress", ProgressBar)
            progress.progress = coverage["completed"]

        self._update_status()

        # Persist finding to DB
        if self.engagement and self.current_engagement_id:
            try:
                await self.engagement.record_finding(
                    engagement_id=self.current_engagement_id,
                    tool=tool_name,
                    target=self.current_target,
                    params=params,
                    raw_output=result.raw,
                    parsed_output=result.parsed,
                )
            except Exception:
                pass  # DB persistence is best-effort; don't interrupt the user

        self.notify(f"{tool_name} completed", severity="information")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_default_params(self, tool_name: str) -> dict:
        """Return a sensible initial parameter dict for the given tool and target."""
        target = self.current_target

        # Tools that expect a URL
        url_tools = {"gobuster", "dirb", "wpscan", "ffuf", "sqlmap", "nikto"}
        # Tools that expect a bare domain
        domain_tools = {"subfinder", "amass", "dnsrecon", "theharvester"}
        # Tools that expect a target + extra args
        net_tools = {"nmap", "whatweb", "enum4linux"}

        if tool_name in url_tools:
            url = target if target.startswith("http") else f"http://{target}"
            params: dict = {"url": url}
            if tool_name == "gobuster":
                params["mode"] = "dir"
                params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
            elif tool_name == "ffuf":
                if "FUZZ" not in url:
                    params["url"] = f"{url}/FUZZ"
                params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
            return params

        if tool_name in domain_tools:
            return {"domain": target}

        if tool_name in net_tools:
            return {"target": target}

        if tool_name == "custom_script":
            return {
                "script": "# Replace with your script",
                "language": "bash",
                "timeout": 120,
            }

        # Exploitation tools — generic target + common extra fields
        extra: dict[str, dict] = {
            "hydra": {"target": target, "service": "ssh", "userlist": "", "passlist": ""},
            "john": {"hash_file": "", "wordlist": "/usr/share/wordlists/rockyou.txt"},
            "hashcat": {"hash": "", "mode": "0", "wordlist": "/usr/share/wordlists/rockyou.txt"},
            "searchsploit": {"query": target},
            "crackmapexec": {"target": target, "protocol": "smb"},
            "metasploit": {"target": target, "module": ""},
            "responder": {"interface": "eth0"},
            "smbclient": {"target": target, "share": ""},
            "evil-winrm": {"target": target, "username": "", "password": ""},
        }
        return extra.get(tool_name, {"target": target})

    def _summarize_result(self, result: Any) -> str:
        """Return a one-line summary of a ToolResult."""
        parsed = result.parsed
        if not parsed:
            lines = result.raw.get("stdout", "").strip().split("\n")
            count = len([l for l in lines if l])
            return f"{count} lines of output"

        if "hosts" in parsed:
            ports_total = sum(len(h.get("ports", [])) for h in parsed["hosts"])
            return f"{len(parsed['hosts'])} host(s), {ports_total} port(s)"
        if "subdomains" in parsed:
            return f"{parsed.get('count', len(parsed['subdomains']))} subdomains found"
        if "exploits" in parsed:
            return f"{parsed.get('count', len(parsed['exploits']))} exploits found"
        if "technologies" in parsed:
            return f"{len(parsed['technologies'])} technologies detected"
        if "vulnerabilities" in parsed:
            return f"{len(parsed['vulnerabilities'])} vulnerabilities found"
        return "completed"

    def _update_status(self) -> None:
        """Refresh the status-text widget beneath the progress bar."""
        parts: list[str] = [
            f"[cyan]Findings:[/cyan] {self.findings_count}",
            f"[cyan]Target:[/cyan] {self.current_target or '[dim]not set[/dim]'}",
        ]
        if self.methodology:
            coverage = self.methodology.get_coverage()
            pct = coverage["coverage_percent"]
            parts.append(f"[cyan]PTES:[/cyan] {pct}%")
        if self.current_engagement_id:
            parts.append(
                f"[cyan]Engagement:[/cyan] [dim]{self.current_engagement_id[:8]}[/dim]"
            )
        self.query_one("#status-text", Static).update("  |  ".join(parts))
