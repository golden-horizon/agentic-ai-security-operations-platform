import json
from agent.local_llm import ask_local_model
from intelligence.mitre_search import search_mitre


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


def analyze_incident(incident: dict) -> dict:
    search_query = detect_search_query(incident)
    mitre_results = search_mitre(search_query, limit=1)

    selected_mitre = mitre_results[0] if mitre_results else {
        "id": "Manual Review",
        "name": "Unknown",
        "score": 0,
        "description": "No reliable MITRE technique found."
    }

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

Return this format:

INCIDENT SUMMARY:
RISK:
MITRE ATT&CK:
RECOMMENDED ACTIONS:
ESCALATION:
"""

    analysis = ask_local_model(prompt)

    return {
        "incident": incident,
        "mitre_search_query": search_query,
        "selected_mitre": selected_mitre,
        "analysis": analysis
    }