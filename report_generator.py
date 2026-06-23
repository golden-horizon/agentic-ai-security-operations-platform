import json
from tools import analyze_incident
from models import IncidentReport

with open("sample_incidents.json", "r") as file:
    incidents = json.load(file)

reports = []

for index, incident in enumerate(incidents, start=1):
    result = analyze_incident(incident)

    report = IncidentReport(
        report_id=f"SOC-{index:03}",
        user=incident.get("user", "N/A"),
        source_ip=incident.get("source_ip", "N/A"),
        attack_type=result["attack_type"],
        severity=result["severity"],
        mitre=result["mitre"],
        reason=result["reason"],
        recommended_actions=result["recommended_actions"]
    )

    reports.append(report.model_dump())

with open("incident_reports.json", "w") as file:
    json.dump(reports, file, indent=4)

print("Structured incident reports saved to incident_reports.json")