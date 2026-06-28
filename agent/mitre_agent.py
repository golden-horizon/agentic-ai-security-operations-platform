from agent.llm_agent import LLMAgent


class MITREAgent(LLMAgent):
    """
    Specialist agent for MITRE ATT&CK mapping.
    Returns structured MITRE data.
    """

    def map_to_mitre(self, incident: dict) -> dict:
        request = incident.get("request", "").lower()

        if "' or '1'='1" in request or "union select" in request:
            return {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": "High",
                "explanation": (
                    "The request contains SQL injection syntax targeting a public-facing "
                    "login endpoint, which aligns with exploiting a public-facing application."
                ),
            }

        if "<script>" in request:
            return {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": "Medium",
                "explanation": (
                    "The request contains XSS-style script syntax targeting a web application."
                ),
            }

        return {
            "technique_id": "Unknown",
            "technique_name": "Unknown",
            "tactic": "Unknown",
            "confidence": "Low",
            "explanation": "No clear MITRE ATT&CK mapping was identified from the incident.",
        }


if __name__ == "__main__":
    agent = MITREAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    result = agent.map_to_mitre(test_incident)

    print("\n=== MITRE AGENT TEST ===")
    print(result)