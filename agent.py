import json
from tools import analyze_incident

with open("sample_incidents.json", "r") as file:
    incidents = json.load(file)

for index, incident in enumerate(incidents, start=1):
    result = analyze_incident(incident)

    print("\n==============================")
    print(f"AI SOC Agent Report #{index}")
    print("==============================")
    print(f"User: {incident.get('user', 'N/A')}")
    print(f"Source IP: {incident.get('source_ip', 'N/A')}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Severity: {result['severity']}")
    print(f"MITRE ATT&CK: {result['mitre']}")
    print(f"Reason: {result['reason']}")
    print("Recommended Actions:")

    for action in result["recommended_actions"]:
        print(f"- {action}")