from agent.llm_agent import LLMAgent

from agent.display import app_header, agent_panel, success


class RemediationAgent(LLMAgent):
    """
    Specialist agent responsible only for response and remediation guidance.
    It does not perform MITRE mapping, CVE lookup, or final SOC decision-making.
    """

    def recommend_actions(self, incident: dict, context: dict | None = None) -> str:
        prompt = f"""
You are a cybersecurity remediation specialist.

Your job is to recommend practical response actions for this incident.

Incident:
{incident}

Additional Context:
{context or "No additional context provided"}

Important rules:
- Do not perform MITRE mapping.
- Do not perform CVE lookup.
- Do not make the final SOC escalation decision.
- Focus only on response and remediation actions.
- Prioritize actions by urgency.
- Keep recommendations practical for a SOC analyst.

Return your answer in this structure:

1. Immediate Containment Actions:
2. Investigation Actions:
3. Eradication / Remediation Actions:
4. Recovery Actions:
5. Prevention Improvements:
6. Owner Teams:
7. Notes / Assumptions:
"""

        return self.ask_llm(prompt)


if __name__ == "__main__":
    agent = RemediationAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
        "risk_score": 70,
        "priority": "High",
    }

    result = agent.recommend_actions(test_incident)

    app_header()
    success("Remediation Agent completed")
    agent_panel("Remediation Agent", result)