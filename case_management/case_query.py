import sys

from rich.console import Console
from rich.table import Table

from case_management.case_repository import CaseRepository


console = Console()


def search_cases(query: str) -> None:
    repository = CaseRepository()
    cases = repository.list_cases()

    query_lower = query.lower()
    matches = []

    for case in cases:
        incident = case.get("incident", {})

        searchable_text = " ".join(
            [
                case.get("case_id", ""),
                case.get("status", ""),
                case.get("soc_decision", ""),
                incident.get("attack_type", ""),
                incident.get("source_ip", ""),
                incident.get("user", ""),
                incident.get("request", ""),
                incident.get("raw_log", ""),
            ]
        ).lower()

        if query_lower in searchable_text:
            matches.append(case)

    table = Table(
        title=f"Case Search Results for: {query}",
        border_style="cyan",
    )

    table.add_column("Case ID", style="bold cyan", width=28)
    table.add_column("Status", style="yellow", width=10)
    table.add_column("Attack Type", style="magenta", width=20)
    table.add_column("Source IP", style="white", width=16)
    table.add_column("User", style="white", width=22)
    table.add_column("Decision", style="green", width=35)
    table.add_column("Events", style="bold yellow", width=8)
    table.add_column("Last Seen", style="white", width=24)

    for case in matches:
        incident = case.get("incident", {})

        table.add_row(
            case.get("case_id", "unknown"),
            case.get("status", "unknown"),
            incident.get("attack_type", "unknown"),
            incident.get("source_ip", "unknown"),
            incident.get("user", "unknown"),
            case.get("soc_decision", "unknown"),
        )

    console.print(table)
    console.print(f"[bold green]Matches found:[/bold green] {len(matches)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python -m case_management.case_query SEARCH_TERM")
    else:
        search_cases(" ".join(sys.argv[1:]))