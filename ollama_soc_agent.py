import json
import requests
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"
INCIDENT_FILE = Path("sample_incidents.json")
OUTPUT_FILE = Path("reports/ollama_incident_reports.json")


def classify_incident(event):
    request = event.get("request", "").lower()
    event_text = event.get("event", "").lower()

    if event.get("failed_attempts", 0) >= 5:
        return "Brute Force", "High", "T1110"

    if "or '1'='1" in request or "select" in request:
        return "SQL Injection", "Critical", "T1190"

    if "<script>" in request:
        return "Cross-Site Scripting (XSS)", "High", "T1059"

    if event.get("request_count", 0) >= 100:
        return "API Abuse", "High", "T1499"

    if event.get("session_anomaly") or "impossible travel" in event_text:
        return "Session Hijacking", "Critical", "T1550"

    return "Unknown", "Medium", "Unknown"


def analyze_incident(event):
    attack_type, severity, mitre = classify_incident(event)

    prompt = f"""
You are a SOC analyst.

Analyze this security event:

Attack Type: {attack_type}
Severity: {severity}
Source IP: {event.get("source_ip", "unknown")}
User: {event.get("user", "unknown")}
MITRE Technique: {mitre}
Raw Event: {json.dumps(event)}

Give:
1. Short summary
2. Why it is dangerous
3. Recommended actions
4. Escalation level
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=120,
    )

    response.raise_for_status()

    return {
        "attack_type": attack_type,
        "severity": severity,
        "source_ip": event.get("source_ip", "unknown"),
        "user": event.get("user", "unknown"),
        "mitre": mitre,
        "analysis": response.json()["response"],
    }


def main():
    events = json.loads(INCIDENT_FILE.read_text())

    reports = []

    for event in events:
        attack_type, _, _ = classify_incident(event)
        print(f"\nAnalyzing: {attack_type} from {event.get('source_ip', 'unknown')}")

        report = analyze_incident(event)
        reports.append(report)

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(reports, indent=2))

    print(f"\nDone. Reports saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()