import json
import ollama


incident = {
    "attack_type": "SQL Injection",
    "severity": "Critical",
    "source_ip": "103.22.55.9",
    "target_user": "guest",
    "mitre": "T1190",
    "description": "Suspicious SQL payload detected in web request parameters."
}


prompt = f"""
You are a SOC Level 1 analyst assistant.

Analyze this incident:

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
    model="qwen2.5:3b",
    messages=[
        {
            "role": "system",
            "content": "You are a cybersecurity SOC analyst assistant."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]
)

print(response["message"]["content"])