from agent.display import app_header, success, agent_panel, incident_summary, zero_day_panel
from agent.mitre_agent import MITREAgent
from agent.threat_intel_agent import ThreatIntelAgent
from agent.remediation_agent import RemediationAgent
import json
from pathlib import Path


class SOCManagerAgent:

    def __init__(self):
        self.mitre_agent = MITREAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.remediation_agent = RemediationAgent()

    def investigate(self, incident: dict) -> dict:
        mitre_result = self.mitre_agent.map_to_mitre(incident)
        threat_result = self.threat_intel_agent.analyze_threat_intel(incident)
        remediation_result = self.remediation_agent.recommend_actions(incident)

        return {
            "incident": incident,
            "mitre_analysis": mitre_result,
            "threat_intelligence": threat_result,
            "remediation": remediation_result,
        }

    def save_report(self, report: dict):
        output_file = Path("reports/multi_agent_investigation.json")

        output_file.parent.mkdir(exist_ok=True)

        output_file.write_text(
            json.dumps(report, indent=2)
        )

        return output_file

        return {
            "incident": incident,
            "mitre_analysis": mitre_result,
            "threat_intelligence": threat_result,
            "remediation": remediation_result,
        }


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

    threat_package = (
        result["threat_intelligence"]
        ["intelligence_package"]
    )

    if threat_package["possible_zero_day"]:
        zero_day_panel()

    report_file = manager.save_report(result)

    success("Multi-agent investigation completed")
    success(f"Report saved: {report_file}")

    if threat_package["possible_zero_day"]:
        zero_day_panel()

    agent_panel("MITRE Agent", result["mitre_analysis"])

    agent_panel(
        "Threat Intel Agent",
        result["threat_intelligence"]["summary"]
    )

    agent_panel("Remediation Agent", result["remediation"])
