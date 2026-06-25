import json
from pathlib import Path
from agent.soc_analyzer import analyze_incident


INPUT_FILE = "sample_incidents.json"
OUTPUT_FILE = "reports/local_soc_reports.json"


def main():
    if not Path(INPUT_FILE).exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    reports = []

    for index, incident in enumerate(incidents, start=1):
        print(f"Analyzing incident {index}/{len(incidents)}...")
        reports.append(analyze_incident(incident))

    Path("reports").mkdir(exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)

    print(f"\nDone. Reports saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()