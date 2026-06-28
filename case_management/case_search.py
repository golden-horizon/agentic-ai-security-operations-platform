import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from case_management.case_repository import CaseRepository


console = Console()


def show_case(case_id: str) -> None:
    repository = CaseRepository()
    case = repository.get_case(case_id)

    if not case:
        console.print(f"[bold red]Case not found:[/bold red] {case_id}")
        return

    incident = case.get("incident", {})
    threat_intel = case.get("threat_intelligence", {}).get("summary", {})
    mitre = case.get("mitre_analysis", {})

    console.print(
        Panel(
            f"""
Case ID: {case.get("case_id")}
Status: {case.get("status")}
Decision: {case.get("soc_decision")}
""",
            title="Case Found",
            border_style="green",
        )
    )

    table = Table(title="Case Details", border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Attack Type", incident.get("attack_type", "unknown"))
    table.add_row("Source IP", incident.get("source_ip", "unknown"))
    table.add_row("User", incident.get("user", "unknown"))
    table.add_row("Request", incident.get("request", "unknown"))
    table.add_row("MITRE ID", mitre.get("technique_id", "unknown"))
    table.add_row("MITRE Name", mitre.get("technique_name", "unknown"))
    table.add_row("Risk Score", str(threat_intel.get("risk_score", "unknown")))
    table.add_row("Priority", threat_intel.get("priority", "unknown"))

    console.print(table)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python -m case_management.case_search CASE-ID")
    else:
        show_case(sys.argv[1])