from collections import Counter

from rich.console import Console
from rich.table import Table

from case_management.case_repository import CaseRepository


console = Console()


def show_statistics() -> None:
    repository = CaseRepository()
    cases = repository.list_cases()

    total_cases = len(cases)

    status_counter = Counter()
    attack_counter = Counter()
    priority_counter = Counter()
    source_ip_counter = Counter()

    for case in cases:
        incident = case.get("incident", {})
        threat_summary = case.get("threat_intelligence", {}).get("summary", {})

        status_counter[case.get("status", "unknown")] += 1
        attack_counter[incident.get("attack_type", "unknown")] += 1
        priority_counter[threat_summary.get("priority", "unknown")] += 1
        source_ip_counter[incident.get("source_ip", "unknown")] += 1

    table = Table(title="Case Statistics", border_style="cyan")
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Total Cases", str(total_cases))

    console.print(table)

    show_counter_table("Cases by Status", status_counter, "Status")
    show_counter_table("Cases by Attack Type", attack_counter, "Attack Type")
    show_counter_table("Cases by Priority", priority_counter, "Priority")
    show_counter_table("Top Source IPs", source_ip_counter, "Source IP")


def show_counter_table(title: str, counter: Counter, label: str) -> None:
    table = Table(title=title, border_style="green")
    table.add_column(label, style="bold green")
    table.add_column("Count", style="white")

    for item, count in counter.most_common():
        table.add_row(str(item), str(count))

    console.print(table)


if __name__ == "__main__":
    show_statistics()