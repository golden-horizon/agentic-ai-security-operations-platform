import json
import ollama
from pathlib import Path


INPUT_FILE = "sample_incidents.json"
OUTPUT_FILE = "local_incident_reports.json"
MODEL_NAME = "qwen2.5:3b"


def analyze_incident(incident: dict) -> str:
    prompt = f"""
You are a SOC Level 1 analyst assistant.

Analyze this security incident:

{json.dumps(incident, indent=2)}

Rules:
- Be practical, not dramatic.
- Do not recommend shutting down all services unless there is confirmed active compromise.
- Give SOC-style actions.
- Use simple language.

Return this format:

INCIDENT SUMMARY:
RISK:
MITRE ATT&CK:
RECOMMENDED ACTIONS:
ESCALATION:
"""

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a cybersecurity SOC analyst assistant."},
            {"role": "user", "content": prompt}
        ]
    )

    return response["message"]["content"]


def main():
    input_path = Path(INPUT_FILE)

    if not input_path.exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    reports = []

    for index, incident in enumerate(incidents, start=1):
        print(f"\nAnalyzing incident {index}/{len(incidents)}...")

        analysis = analyze_incident(incident)

        reports.append({
            "incident": incident,
            "local_model": MODEL_NAME,
            "analysis": analysis
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)

    print(f"\nDone. Reports saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()