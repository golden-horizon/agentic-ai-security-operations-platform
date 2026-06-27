class IOCAgent:
    """
    Deterministic IOC extraction agent.
    Uses Python logic instead of an LLM.
    """

    def extract_iocs(self, incident: dict) -> dict:

        request = incident.get("request", "").lower()

        attack_pattern = "Unknown"

        if "' or '1'='1" in request:
            attack_pattern = "SQL Injection"

        elif "union select" in request:
            attack_pattern = "SQL Injection"

        elif "<script>" in request:
            attack_pattern = "Cross-Site Scripting (XSS)"

        return {
            "source_ip": incident.get("source_ip", "Not observed"),
            "user": incident.get("user", "Not observed"),
            "request": incident.get("request", "Not observed"),
            "attack_pattern": attack_pattern,
        }


if __name__ == "__main__":
    from agent.display import ioc_panel

    agent = IOCAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    result = agent.extract_iocs(test_incident)

    ioc_panel(result)