from rich.console import Console

from case_management.case_repository import CaseRepository
from threat_intel.ip_reputation import IPReputation


console = Console()


def enrich_existing_cases() -> None:
    repository = CaseRepository()
    ip_reputation = IPReputation()

    cases = repository.list_cases()
    updated_count = 0

    for case in cases:
        incident = case.get("incident", {})
        source_ip = incident.get("source_ip", "unknown")

        enrichment = ip_reputation.lookup(source_ip)

        case["threat_enrichment"] = enrichment

        repository.save_case(case)
        updated_count += 1

    console.print("[bold green]Existing cases enriched[/bold green]")
    console.print(f"[cyan]Cases updated:[/cyan] {updated_count}")


if __name__ == "__main__":
    enrich_existing_cases()