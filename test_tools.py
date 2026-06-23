from soc_tools import map_attack, calculate_severity, map_mitre, recommend_actions

incident = {
    "user": "admin",
    "source_ip": "45.83.12.10",
    "failed_attempts": 8
}

print("=== AI SOC Agent Report ===")
print("Attack Type:", map_attack(incident))
print("Severity:", calculate_severity(incident))
print("MITRE ATT&CK:", map_mitre(incident))

print("\nRecommended Actions:")
for action in recommend_actions(incident):
    print("-", action)