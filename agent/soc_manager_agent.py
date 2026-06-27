import json
from pathlib import Path

from agent.display import (
    app_header,
    success,
    agent_panel,
    incident_summary,
    zero_day_panel,
    decision_panel,
    ioc_panel,
)
from agent.ioc_agent import IOCAgent
from agent.llm_agent import LLMAgent
from agent.mitre_agent import MITREAgent
from agent.remediation_agent import RemediationAgent
from agent.threat_intel_agent import ThreatIntelAgent
from case_management.investigation_case import InvestigationCase
from engine.decision_engine import DecisionEngine


class SOCManagerAgent(LLMAgent):
    """
    Orchestrates specialist agents and creates a final executive summary.
    """

    def __init__(self):
        super().__init__()
        self.ioc_agent = IOCAgent()
        self.mitre_agent = MITREAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.remediation_agent = RemediationAgent()

    def investigate(self, incident: dict) -> dict:
        case = InvestigationCase(incident)

        case.iocs = self.ioc_agent.extract_iocs(incident)
        case.mitre_analysis = self.mitre_agent.map_to_mitre(incident)

        case.threat_intelligence = self.threat_intel_agent.analyze_threat_intel(
            incident
        )

        threat_package = case.threat_intelligence["intelligence_package"]

        case.soc_decision = DecisionEngine.make_decision(
            risk_score=threat_package["risk_score"],
            priority=threat_package["priority"],
            possible_zero_day=threat_package["possible_zero_day"],
            kev_found=threat_package["evidence"]["cisa_kev"]["found"],
        )

        case.remediation = self.remediation_agent.recommend_actions(incident)

        case.executive_summary = self.create_executive_summary(case.to_dict())

        return case.to_dict()

    def create_executive_summary(self, case_data: dict) -> str:
        prompt = f"""
You are a senior SOC incident commander.

Create a final executive investigation summary based on the structured case data.

Important rules:
- Do not invent evidence.
- Clearly separate confirmed facts from assumptions.
- The official SOC decision is already provided in the case data.
- Do not create a new decision.
- Explain the provided SOC decision.
- Do not call this a zero-day unless the intelligence package says possible_zero_day is True.
- Keep the language professional and concise.
- Do not describe an attack as confirmed unless successful compromise is proven.
- If only suspicious requests are observed, describe it as an attempted attack.
- Never invent cybersecurity acronyms.
- Use only CVE, CISA KEV, MITRE ATT&CK, IOC, and TTP.

Structured Case Data:
{case_data}

Return your answer in this structure:

1. SOC Decision:
2. Executive Summary:
3. Confirmed Facts:
4. Assumptions / Unknowns:
5. Business Impact:
6. Immediate Next Steps:
7. Confidence:
"""

        return self.ask_llm(prompt)

    def save_report(self, report: dict):
        output_file = Path("reports/multi_agent_investigation.json")
        output_file.parent.mkdir(exist_ok=True)
        output_file.write_text(json.dumps(report, indent=2))
        return output_file


if __name__ == "__main__":
    app_header()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    incident_summary(test_incident)

    manager = SOCManagerAgent()
    result = manager.investigate(test_incident)

    threat_package = result["threat_intelligence"]["intelligence_package"]

    report_file = manager.save_report(result)

    success("Multi-agent investigation completed")
    success(f"Report saved: {report_file}")

    decision_panel(result["soc_decision"])
    ioc_panel(result["iocs"])

    if threat_package["possible_zero_day"]:
        zero_day_panel()

    agent_panel("MITRE Agent", result["mitre_analysis"])
    agent_panel("Threat Intel Agent", result["threat_intelligence"]["summary"])
    agent_panel("Remediation Agent", result["remediation"])
    agent_panel("SOC Manager", result["executive_summary"])