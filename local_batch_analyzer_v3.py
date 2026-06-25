import json
import ollama
from pathlib import Path
from mitreattack.stix20 import MitreAttackData


INPUT_FILE = "sample_incidents.json"
OUTPUT_FILE = "local_incident_reports_v3.json"
MODEL_NAME = "qwen2.5:3b"
ATTACK_JSON_FILE = "enterprise-attack.json"


def detect_search_query(incident: dict) -> str:
    request = incident.get("request", "").lower()
    event = incident.get("event", "").lower()
    endpoint = incident.get("endpoint", "").lower()
    failed_attempts = incident.get("failed_attempts", 0)
    request_count = incident.get("request_count", 0)

    if failed_attempts >= 5:
        return "brute force"

    if "or '1'='1" in request or "sql" in request:
        return "public-facing application"

    if "<script>" in request:
        return "public-facing application"

    if request_count >= 100 and "/api/login" in endpoint:
        return "brute force"

    if "impossible travel" in event or incident.get("session_anomaly") is True:
        return "valid accounts"

    return "suspicious activity"


def search_mitre_techniques(keyword: str, limit: int = 3):
    attack_data = MitreAttackData(ATTACK_JSON_FILE)
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

    results = []

    for technique in techniques:
        name = technique.get("name", "")
        description = technique.get("description", "")
        text = f"{name} {description}".lower()

        if keyword.lower() in text:
            external_id = "Unknown"

            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "Unknown")

            results.append({
                "id": external_id,
                "name": name,
                "description": description[:500]
            })

    return results[:limit]


def analyze_incident(incident: dict, mitre_results: list) -> str:
    prompt = f"""
You are a SOC Level 1 analyst assistant.

Analyze this security incident:

{json.dumps(incident, indent=2)}

Here are MITRE ATT&CK search results from official ATT&CK data:

{json.dumps(mitre_results, indent=2)}

Rules:
- Choose the most relevant MITRE technique from the provided MITRE results only.
- Do not invent a MITRE ID.
- If none of the results fit, say "MITRE mapping requires manual review".
- Be practical, not dramatic.
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
    if not Path(INPUT_FILE).exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    if not Path(ATTACK_JSON_FILE).exists():
        print(f"ERROR: {ATTACK_JSON_FILE} not found. Run mitre_lookup.py first.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    reports = []

    for index, incident in enumerate(incidents, start=1):
        print(f"\nAnalyzing incident {index}/{len(incidents)}...")

        search_query = detect_search_query(incident)
        mitre_results = search_mitre_techniques(search_query)

        analysis = analyze_incident(incident, mitre_results)

        reports.append({
            "incident": incident,
            "mitre_search_query": search_query,
            "mitre_results": mitre_results,
            "local_model": MODEL_NAME,
            "analysis": analysis
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)

    print(f"\nDone. Reports saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()