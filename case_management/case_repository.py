import json
from pathlib import Path


class CaseRepository:
    """
    Stores and retrieves investigation cases from JSON files.
    """

    def __init__(self, storage_dir: str = "reports/cases"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_case(self, case: dict) -> Path:
        case_id = case["case_id"]
        output_file = self.storage_dir / f"{case_id}.json"

        output_file.write_text(
            json.dumps(case, indent=2)
        )

        return output_file

    def list_cases(self) -> list[dict]:
        cases = []

        for file in self.storage_dir.glob("*.json"):
            case_data = json.loads(file.read_text())
            cases.append(case_data)

        return cases

    def get_case(self, case_id: str) -> dict | None:
        case_file = self.storage_dir / f"{case_id}.json"

        if not case_file.exists():
            return None

        return json.loads(case_file.read_text())


if __name__ == "__main__":
    repository = CaseRepository()

    cases = repository.list_cases()

    print("\n=== CASE REPOSITORY TEST ===")
    print(f"Cases found: {len(cases)}")