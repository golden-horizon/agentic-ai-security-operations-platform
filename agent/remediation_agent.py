class RemediationAgent:
    """
    Structured remediation agent.
    Returns actionable response plans.
    """

    def recommend_actions(self, incident: dict) -> dict:

        request = incident.get("request", "").lower()

        immediate_actions = []
        investigation_actions = []
        remediation_actions = []
        recovery_actions = []
        prevention_actions = []
        owner_teams = ["Security Team"]

        # SQL Injection
        if "' or '1'='1" in request or "union select" in request:

            immediate_actions.extend([
                "Block source IP",
                "Review web application logs",
            ])

            investigation_actions.extend([
                "Review authentication logs",
                "Check database logs",
                "Verify no unauthorized access occurred",
            ])

            remediation_actions.extend([
                "Implement parameterized queries",
                "Validate user input",
                "Deploy WAF protections",
            ])

            prevention_actions.extend([
                "Conduct secure coding review",
                "Schedule web application penetration testing",
            ])

            owner_teams.extend([
                "Application Team",
                "DevOps Team",
            ])

        # XSS
        elif "<script>" in request:

            immediate_actions.extend([
                "Block malicious requests",
                "Review affected pages",
            ])

            remediation_actions.extend([
                "Implement output encoding",
                "Sanitize user input",
            ])

            prevention_actions.extend([
                "Enable Content Security Policy",
            ])

        return {
            "immediate_actions": immediate_actions,
            "investigation_actions": investigation_actions,
            "remediation_actions": remediation_actions,
            "recovery_actions": recovery_actions,
            "prevention_actions": prevention_actions,
            "owner_teams": owner_teams,
        }


if __name__ == "__main__":

    agent = RemediationAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    result = agent.recommend_actions(test_incident)

    print("\n=== REMEDIATION TEST ===")
    print(result)