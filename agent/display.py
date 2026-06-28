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
    "IOC Agent": ("cyan", "🟦"),
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
    title = (
        f"{emoji} [bold {color}]{agent_name}[/bold {color}] [green]✓ {status}[/green]"
    )

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


def zero_day_panel() -> None:
    console.print(
        Panel(
            "[bold red]⚠ POSSIBLE ZERO-DAY OR UNTRACKED EXPLOIT BEHAVIOR[/bold red]\n\n"
            "Risk Score: 70\n"
            "Priority: High\n"
            "No CVE match found.\n"
            "No CISA KEV match found.\n"
            "Further investigation required.",
            title="CRITICAL ALERT",
            border_style="red",
        )
    )


def decision_panel(decision: str) -> None:
    console.print(
        Panel(
            f"[bold yellow]{decision}[/bold yellow]",
            title="SOC DECISION",
            border_style="yellow",
        )
    )
def ioc_panel(iocs: dict) -> None:
    table = Table(title="Indicators of Compromise", border_style="cyan")

    table.add_column("Indicator", style="bold cyan")
    table.add_column("Value", style="white")

    for key, value in iocs.items():
        table.add_row(str(key), str(value))

    console.print(table)

def remediation_table(remediation: dict):
    table = Table(
        title="Remediation Plan",
        border_style="green",
    )

    table.add_column(
        "Category",
        style="bold green",
        width=18,
    )

    table.add_column(
        "Action",
        style="white",
    )

    for item in remediation["immediate_actions"]:
        table.add_row("Immediate", item)

    for item in remediation["investigation_actions"]:
        table.add_row("Investigation", item)

    for item in remediation["remediation_actions"]:
        table.add_row("Remediation", item)

    for item in remediation["recovery_actions"]:
        table.add_row("Recovery", item)

    for item in remediation["prevention_actions"]:
        table.add_row("Prevention", item)

    console.print(table)   

def timeline_table(timeline: list[dict]) -> None:
    table = Table(
        title="Case Timeline",
        border_style="blue",
    )

    table.add_column(
        "Step",
        style="bold blue",
        width=6,
    )

    table.add_column(
        "Time",
        style="white",
    )

    table.add_column(
        "Event",
        style="cyan",
    )

    for index, item in enumerate(timeline, start=1):
        table.add_row(
            str(index),
            item["time"],
            item["event"],
        )

    console.print(table)    
