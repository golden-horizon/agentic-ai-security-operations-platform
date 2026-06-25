import json
import ollama
from pathlib import Path
from mitre_search_engine import search_mitre


INPUT_FILE = "sample_incidents.json"
OUTPUT_FILE = "local_incident_reports_v4.json"
MODEL_NAME = "qwen2.5:3b"


def detect_search_query(incident: dict) -> str:
    request = incident.get("request", "").lower()
    event = incident.get("event", "").lower()
    endpoint = incident.get("endpoint", "").lower()
    failed_attempts = incident.get("failed_attempts", 0)
    request_count = incident.get("request_count", 0)

    if failed_attempts >= 5:
        return "brute force"

    if "or '1'='1" in request or "sql" in request:
        return "exploit public-facing application"

    if "<script>" in request:
        return "exploit public-facing application"

    if request_count >= 100 and "/api/login" in endpoint:
        return "brute force"

    if "impossible travel" in event or incident.get("session_anomaly") is True:
        return "valid accounts"

    return "suspicious activity"


def analyze_incident(incident: dict, selected_mitre: dict) -> str:
    prompt = f"""
You are a SOC Level 1 analyst assistant.

Analyze this security incident:

{json.dumps(incident, indent=2)}

This is the verified MITRE ATT&CK mapping selected by the local MITRE search engine:

{json.dumps(selected_mitre, indent=2)}

Rules:
- Use only the verified MITRE mapping above.
- Do not choose another MITRE technique.
- Do not invent a MITRE ID.
- Be practical, not dramatic.
- Give SOC-style actions.
- Use simple language.
- Escalate if the incident suggests credential compromise, public-facing app exploit, or session anomaly.

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
    if not Path(INPUT_FILE).exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    reports = []

    for index, incident in enumerate(incidents, start=1):
        print(f"\nAnalyzing incident {index}/{len(incidents)}...")

        search_query = detect_search_query(incident)
        mitre_results = search_mitre(search_query, limit=1)

        if mitre_results:
            selected_mitre = mitre_results[0]
        else:
            selected_mitre = {
                "id": "Manual Review",
                "name": "Unknown",
                "score": 0,
                "description": "No reliable MITRE technique found."
            }

        analysis = analyze_incident(incident, selected_mitre)

        reports.append({
            "incident": incident,
            "mitre_search_query": search_query,
            "selected_mitre": selected_mitre,
            "local_model": MODEL_NAME,
            "analysis": analysis
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)

    print(f"\nDone. Reports saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()