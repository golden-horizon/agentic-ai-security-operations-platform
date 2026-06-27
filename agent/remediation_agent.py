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
- Distinguish between an attempted attack and a confirmed compromise.
- If compromise is not confirmed, do not assume the attacker gained access.
- Avoid recommending disruptive actions unless supported by evidence.
- Prefer investigation and monitoring actions when evidence is limited.
- Clearly identify precautionary recommendations.
- Do not assume the technology stack.
- Do not assume SQL Server, ASP.NET, Windows, Linux, cloud provider, or database type unless explicitly provided.
- Use neutral wording like "database", "web application", or "authentication service".
- Do not claim a breach occurred unless evidence confirms successful access.
- Treat this as an attempted attack unless logs prove compromise.
- Do not provide technology examples unless they appear in the incident data.
- Do not use phrases such as "e.g. ASP.NET", "e.g. SQL Server", or similar examples.
- Keep recommendations technology-neutral when the environment is unknown.
- Do not use words like "compromised system" unless compromise is confirmed.
- For attempted attacks, recommend blocking, monitoring, log review, and code review before disruptive actions.
Return your answer in this structure:

1. Immediate Containment Actions:
2. Investigation Actions:
3. Eradication / Remediation Actions
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