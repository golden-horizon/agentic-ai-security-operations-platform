from agent.llm_agent import LLMAgent
from intelligence.intelligence_manager import build_intelligence_package


class ThreatIntelAgent(LLMAgent):
    """
    Specialist agent for summarizing threat intelligence evidence.
    It uses the Intelligence Manager, then explains the evidence clearly.
    """

    def analyze_threat_intel(self, incident: dict) -> str:
        intelligence_package = build_intelligence_package(incident)

        prompt = f"""
You are a threat intelligence analyst.

Your job is to explain the threat intelligence evidence for this incident.

Important rules:
- Do not make the final SOC decision.
- Do not provide full remediation steps.
- Focus only on threat intelligence evidence.
- Separate direct evidence from enrichment evidence.
- If no CVE is linked, clearly say no CVE evidence is available.

Intelligence Package:
{intelligence_package}

Return your answer in this structure:

1. Threat Summary:
2. Direct Evidence:
3. Enrichment Evidence:
4. Risk Score:
5. Priority:
6. Confidence:
"""

        return self.ask_llm(prompt)


if __name__ == "__main__":
    agent = ThreatIntelAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    result = agent.analyze_threat_intel(test_incident)

    print("\n=== THREAT INTEL AGENT TEST ===\n")
    print(result)