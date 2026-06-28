from rich.console import Console
from rich.table import Table

from case_management.case_repository import CaseRepository


console = Console()


def show_cases() -> None:
    repository = CaseRepository()
    cases = repository.list_cases()

    table = Table(
        title="Saved Investigation Cases",
        border_style="cyan",
    )

    table.add_column("Case ID", style="bold cyan", width=20)
    table.add_column("Status", style="yellow", width=10)
    table.add_column("Decision", style="green", width=40)
    table.add_column("Attack Type", style="magenta", width=15)
    table.add_column("Source IP", style="white", width=15)
    table.add_column("User", style="white", width=10)

    for case in cases:
        incident = case.get("incident", {})

        table.add_row(
            case.get("case_id", "unknown"),
            case.get("status", "unknown"),
            case.get("soc_decision", "unknown"),
            incident.get("attack_type", "unknown"),
            incident.get("source_ip", "unknown"),
            incident.get("user", "unknown"),
        )

    console.print(table)


if __name__ == "__main__":
    show_cases()