import sys
from datetime import datetime, timezone

from rich.console import Console

from case_management.case_repository import CaseRepository


console = Console()


def close_case(case_id: str, resolution: str = "Investigation completed") -> None:
    repository = CaseRepository()
    case = repository.get_case(case_id)

    if not case:
        console.print(f"[bold red]Case not found:[/bold red] {case_id}")
        return

    case["status"] = "Closed"
    case["closed_at"] = datetime.now(timezone.utc).isoformat()
    case["resolution"] = resolution

    repository.save_case(case)

    console.print(f"[bold green]Case closed:[/bold green] {case_id}")
    console.print(f"[cyan]Resolution:[/cyan] {resolution}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(
            "[yellow]Usage:[/yellow] python -m case_management.case_close CASE-ID \"Resolution text\""
        )
    else:
        case_id = sys.argv[1]
        resolution = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "Investigation completed"

        close_case(case_id, resolution)