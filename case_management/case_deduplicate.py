from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

from rich.console import Console

from case_management.case_repository import CaseRepository
from engine.correlation_engine import CorrelationEngine


console = Console()


def deduplicate_cases() -> None:
    repository = CaseRepository()
    cases = repository.list_cases()

    grouped_cases = defaultdict(list)

    for case in cases:
        incident = case.get("incident", {})
        key = CorrelationEngine.build_correlation_key(incident)
        grouped_cases[key].append(case)

    merged_count = 0

    for key, duplicate_group in grouped_cases.items():
        if len(duplicate_group) <= 1:
            continue

        duplicate_group.sort(
            key=lambda case: case.get("created_at", "")
        )

        master_case = duplicate_group[0]
        duplicates = duplicate_group[1:]

        total_events = master_case.get("event_count", 1)
        related_logs = master_case.get("related_logs", [])

        for duplicate in duplicates:
            total_events += duplicate.get("event_count", 1)

            raw_log = duplicate.get("incident", {}).get("raw_log")
            if raw_log:
                related_logs.append(raw_log)

            for log in duplicate.get("related_logs", []):
                related_logs.append(log)

        master_case["event_count"] = total_events
        master_case["related_logs"] = list(dict.fromkeys(related_logs))
        master_case["last_seen"] = datetime.now(timezone.utc).isoformat()

        repository.save_case(master_case)

        for duplicate in duplicates:
            duplicate_file = Path("reports/cases") / f"{duplicate['case_id']}.json"
            if duplicate_file.exists():
                duplicate_file.unlink()
                merged_count += 1

    console.print(f"[bold green]Deduplication complete[/bold green]")
    console.print(f"[cyan]Duplicate cases removed:[/cyan] {merged_count}")


if __name__ == "__main__":
    deduplicate_cases()