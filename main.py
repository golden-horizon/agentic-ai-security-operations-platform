import json
from agent.soc_analyzer import analyze_incident
from config.settings import SAMPLE_INCIDENTS_FILE, LOCAL_SOC_REPORT_FILE, REPORTS_DIR


def main():
    if not SAMPLE_INCIDENTS_FILE.exists():
        print(f"ERROR: {SAMPLE_INCIDENTS_FILE} not found.")
        return

    with open(SAMPLE_INCIDENTS_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    reports = []

    for index, incident in enumerate(incidents, start=1):
        print(f"Analyzing incident {index}/{len(incidents)}...")
        reports.append(analyze_incident(incident))

    REPORTS_DIR.mkdir(exist_ok=True)

    with open(LOCAL_SOC_REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)

    print(f"\nDone. Reports saved to {LOCAL_SOC_REPORT_FILE}")


if __name__ == "__main__":
    main()