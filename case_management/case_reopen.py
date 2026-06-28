import sys
from datetime import datetime, timezone

from rich.console import Console

from case_management.case_repository import CaseRepository


console = Console()


def reopen_case(case_id: str, reason: str = "Case reopened for further investigation") -> None:
    repository = CaseRepository()
    case = repository.get_case(case_id)

    if not case:
        console.print(f"[bold red]Case not found:[/bold red] {case_id}")
        return

    case["status"] = "Reopened"
    case["reopened_at"] = datetime.now(timezone.utc).isoformat()
    case["reopen_reason"] = reason

    repository.save_case(case)

    console.print(f"[bold green]Case reopened:[/bold green] {case_id}")
    console.print(f"[cyan]Reason:[/cyan] {reason}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(
            "[yellow]Usage:[/yellow] python -m case_management.case_reopen CASE-ID \"Reason text\""
        )
    else:
        case_id = sys.argv[1]
        reason = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "Case reopened for further investigation"

        reopen_case(case_id, reason)