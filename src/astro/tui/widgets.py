"""Custom widgets for the Project Astro TUI."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ToolParameterModal(ModalScreen[dict | None]):
    """Modal dialog for reviewing and customising tool parameters before execution."""

    CSS = """
    ToolParameterModal {
        align: center middle;
    }
    #param-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    .param-label {
        margin-top: 1;
        color: $text-muted;
    }
    .param-input {
        margin-bottom: 1;
    }
    #button-row {
        margin-top: 1;
        align: center middle;
        height: 3;
    }
    """

    def __init__(self, tool_name: str, default_params: dict) -> None:
        super().__init__()
        self.tool_name = tool_name
        self.default_params = default_params
        self._param_inputs: dict[str, Input] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="param-dialog"):
            yield Static(f"[bold]{self.tool_name}[/bold] — Parameters", classes="title")

            for key, value in self.default_params.items():
                yield Static(f"{key}:", classes="param-label")
                inp = Input(
                    value=str(value),
                    placeholder=f"Enter {key}...",
                    id=f"param-{key}",
                    classes="param-input",
                )
                self._param_inputs[key] = inp
                yield inp

            with Horizontal(id="button-row"):
                yield Button("Run", variant="success", id="btn-run")
                yield Button("Cancel", variant="error", id="btn-cancel")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Stop Enter in a param field from bubbling up to AstroApp's input handler."""
        event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            params = {
                key: inp.value
                for key, inp in self._param_inputs.items()
            }
            self.dismiss(params)
        else:
            self.dismiss(None)


class AttackGraphWidget(Static):
    """Renders an ASCII attack graph from AttackGraphBuilder.to_json() data."""

    def render_graph(self, graph_data: dict) -> str:
        """Convert graph_data dict to a Rich-markup string for display."""
        lines: list[str] = []
        nodes: list[dict] = graph_data.get("nodes", [])
        edges: list[dict] = graph_data.get("edges", [])

        hosts = [n for n in nodes if n.get("type") == "host"]
        services = [n for n in nodes if n.get("type") == "service"]
        vulns = [n for n in nodes if n.get("type") == "vulnerability"]

        lines.append("[bold]Attack Graph[/bold]")
        lines.append("=" * 40)

        for host in hosts:
            host_id: str = host["id"]
            lines.append(f"\n[cyan]┌─ {host_id}[/cyan] ({host.get('os', 'unknown')})")

            host_svc_ids = [
                e["target"]
                for e in edges
                if e["source"] == host_id and e.get("relation") == "exposes"
            ]
            for svc_id in host_svc_ids:
                svc = next((s for s in services if s["id"] == svc_id), None)
                if svc is None:
                    continue
                lines.append(
                    f"[cyan]├────[/cyan] {svc['id']} "
                    f"[[yellow]{svc.get('service', '')} {svc.get('version', '')}[/yellow]]"
                )

                vuln_ids = [
                    e["target"]
                    for e in edges
                    if e["source"] == svc_id and e.get("relation") == "vulnerable_to"
                ]
                for vuln_id in vuln_ids:
                    vuln = next((v for v in vulns if v["id"] == vuln_id), None)
                    if vuln is None:
                        continue
                    raw_score = vuln.get("cvss_score")
                    try:
                        score = float(raw_score) if raw_score is not None else 0.0
                    except (TypeError, ValueError):
                        score = 0.0
                    color = "red" if score >= 9.0 else "yellow" if score >= 7.0 else "green"
                    lines.append(
                        f"[cyan]│     └─[/cyan] [{color}]{vuln_id} (CVSS: {score:.1f})[/{color}]"
                    )

        stats: dict = graph_data.get("stats", {})
        lines.append(
            f"\nTotal: [bold]{stats.get('hosts', 0)}[/bold] hosts, "
            f"[bold]{stats.get('services', 0)}[/bold] services, "
            f"[bold]{stats.get('vulnerabilities', 0)}[/bold] vulnerabilities"
        )
        return "\n".join(lines)
