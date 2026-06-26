from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

console = Console()


AGENT_STYLES = {
    "LLM Agent": ("blue", "🟦"),
    "MITRE Agent": ("magenta", "🟪"),
    "Threat Intel Agent": ("yellow", "🟨"),
    "Remediation Agent": ("green", "🟩"),
    "SOC Manager": ("red", "🟥"),
}


def app_header() -> None:
    header = Text()
    header.append("AI SOC AGENT v3.0\n", style="bold cyan")
    header.append("Multi-Agent Security Investigation Platform", style="white")

    console.print(
        Panel(
            header,
            border_style="cyan",
            padding=(1, 6),
            expand=True,
        )
    )


def section(title: str, style: str = "cyan") -> None:
    console.print(Rule(f"[bold {style}]{title}[/bold {style}]", style=style))


def success(message: str) -> None:
    console.print(f"[bold green]✓[/bold green] {message}")


def warning(message: str) -> None:
    console.print(f"[bold yellow]![/bold yellow] {message}")


def error(message: str) -> None:
    console.print(f"[bold red]✗[/bold red] {message}")


def agent_panel(agent_name: str, content: str, status: str = "COMPLETED") -> None:
    color, emoji = AGENT_STYLES.get(agent_name, ("white", "⬜"))
    title = f"{emoji} [bold {color}]{agent_name}[/bold {color}] [green]✓ {status}[/green]"

    console.print(
        Panel(
            Markdown(content),
            title=title,
            border_style=color,
            padding=(1, 2),
            expand=True,
        )
    )


def incident_summary(incident: dict) -> None:
    table = Table(title="Incident Summary", border_style="cyan")

    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    for key, value in incident.items():
        table.add_row(str(key), str(value))

    console.print(table)


def risk_panel(risk_score: int, priority: str) -> None:
    if risk_score >= 80:
        color = "red"
        icon = "🔴"
    elif risk_score >= 60:
        color = "yellow"
        icon = "🟡"
    elif risk_score >= 30:
        color = "blue"
        icon = "🔵"
    else:
        color = "green"
        icon = "🟢"

    content = f"""
Risk Score: [bold {color}]{risk_score}/100[/bold {color}]

Priority: [bold {color}]{icon} {priority}[/bold {color}]
"""

    console.print(
        Panel(
            content,
            title="[bold]Risk Assessment[/bold]",
            border_style=color,
            padding=(1, 2),
            expand=True,
        )
    )


def loading(message: str) -> None:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description=message, total=None)