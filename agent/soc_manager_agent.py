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
    remediation_table,
    timeline_table,
)
from agent.ioc_agent import IOCAgent
from agent.llm_agent import LLMAgent
from agent.mitre_agent import MITREAgent
from agent.remediation_agent import RemediationAgent
from agent.threat_intel_agent import ThreatIntelAgent
from case_management.investigation_case import InvestigationCase
from engine.decision_engine import DecisionEngine


class SOCManagerAgent(LLMAgent):
    def __init__(self):
        super().__init__()
        self.ioc_agent = IOCAgent()
        self.mitre_agent = MITREAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.remediation_agent = RemediationAgent()

    def investigate(self, incident: dict) -> dict:
      case = InvestigationCase(incident)
      case.add_timeline_event("Case created")

      case.iocs = self.ioc_agent.extract_iocs(incident)
      case.add_timeline_event("IOC extraction completed")

      case.mitre_analysis = self.mitre_agent.map_to_mitre(incident)
      case.add_timeline_event("MITRE mapping completed")

      case.threat_intelligence = self.threat_intel_agent.analyze_threat_intel(incident)
      case.add_timeline_event("Threat intelligence completed")

      threat_package = case.threat_intelligence["intelligence_package"]

      case.soc_decision = DecisionEngine.make_decision(
        risk_score=threat_package["risk_score"],
        priority=threat_package["priority"],
        possible_zero_day=threat_package["possible_zero_day"],
        kev_found=threat_package["evidence"]["cisa_kev"]["found"],
    )
      case.add_timeline_event("SOC decision generated")

      case.remediation = self.remediation_agent.recommend_actions(incident)
      case.add_timeline_event("Remediation plan generated")

      summary_context = self.build_summary_context(case.to_dict())
      case.executive_summary = self.create_executive_summary(summary_context)
      case.add_timeline_event("Executive summary generated")

      return case.to_dict()

    def build_summary_context(self, case_data: dict) -> dict:
        threat_summary = case_data["threat_intelligence"]["summary"]

        return {
            "soc_decision": case_data["soc_decision"],
            "incident": case_data["incident"],
            "iocs": case_data["iocs"],
            "mitre": case_data["mitre_analysis"],
            "threat_intel": {
                "risk_score": threat_summary["risk_score"],
                "priority": threat_summary["priority"],
                "ip_reputation": threat_summary["ip_reputation"],
                "ip_confidence": threat_summary["ip_confidence"],
                "cve_found": threat_summary["cve_found"],
                "kev_found": threat_summary["kev_found"],
                "possible_zero_day": threat_summary["possible_zero_day"],
                "zero_day_note": threat_summary["zero_day_note"],
            },
            "remediation": case_data["remediation"],
        }

    def create_executive_summary(self, case_data: dict) -> str:
        prompt = f"""
You are a senior SOC incident commander.

Create a final executive investigation summary based only on the structured case data.

Important rules:
- Do not invent evidence.
- Do not invent MITRE IDs.
- If kev_found is False, do not say CISA KEV identified anything.
- If cve_found is False, do not mention any CVE ID.
- Clearly separate confirmed facts from assumptions.
- The official SOC decision is already provided in the case data.
- Do not create a new decision.
- Explain the provided SOC decision.
- Do not call this a zero-day unless possible_zero_day is True.
- Do not describe an attack as confirmed unless successful compromise is proven.
- If only suspicious requests are observed, describe it as an attempted attack.
- CISA KEV means Known Exploited Vulnerabilities.
- Never expand CISA KEV as Critical Software Asset.
- If kev_found is False, write: "No CISA KEV match was found."
- Say "attack attempt is confirmed" when only the request pattern is confirmed.
- Do not say "attack is confirmed" unless successful compromise is proven.

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
    timeline_table(result["timeline"])

    if threat_package["possible_zero_day"]:
        zero_day_panel()

    agent_panel(
        "MITRE Agent",
        f"""
1. Technique ID: {result["mitre_analysis"]["technique_id"]}
2. Technique Name: {result["mitre_analysis"]["technique_name"]}
3. Tactic: {result["mitre_analysis"]["tactic"]}
4. Confidence: {result["mitre_analysis"]["confidence"]}
5. Explanation: {result["mitre_analysis"]["explanation"]}
""",
    )

    threat_summary = result["threat_intelligence"]["summary"]

    agent_panel(
        "Threat Intel Agent",
        f"""
1. Risk Score: {threat_summary["risk_score"]}
2. Priority: {threat_summary["priority"]}
3. Source IP: {threat_summary["source_ip"]}
4. IP Reputation: {threat_summary["ip_reputation"]}
5. IP Confidence: {threat_summary["ip_confidence"]}%
6. CVE Found: {threat_summary["cve_found"]}
7. CISA KEV Found: {threat_summary["kev_found"]}
8. Possible Zero-Day: {threat_summary["possible_zero_day"]}
9. Note: {threat_summary["zero_day_note"]}
""",
    )

    remediation_table(result["remediation"])
    agent_panel("SOC Manager", result["executive_summary"])