import json
import os
from datetime import datetime

from agents.agent_roles import AGENT_ROLES


class MultiAgentOrchestrator:
    def __init__(self):
        self.workflow = []

    def run(self, incident):
        context = {"incident": incident}

        context = self.log_collection_agent(context)
        context = self.detection_agent(context)
        context = self.mitre_attack_agent(context)
        context = self.threat_intelligence_agent(context)
        context = self.correlation_agent(context)
        context = self.severity_escalation_agent(context)
        context = self.case_management_agent(context)
        context = self.investigation_agent(context)
        print("\n=== AGENT WORKFLOW ===")

        for step in self.workflow:
          print(f"→ {step['agent']}")

        print("======================\n")

        report = {
            "generated_at": datetime.now().isoformat(),
            "case_id": incident.get("case_id"),
            "final_investigation": context,
            "workflow": self.workflow,
        }

    
        os.makedirs("../reports", exist_ok=True)

        with open("../reports/multi_agent_investigation.json", "w") as f:
            json.dump(report, f, indent=4)

        print("✅ Multi-agent investigation completed")
        return report

    def add_step(self, agent_name, input_data, output_data):
        self.workflow.append({
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "input": input_data,
            "output": output_data,
        })

    def log_collection_agent(self, context):
        incident = context["incident"]

        output = {
            "normalized_event": {
                "case_id": incident.get("case_id"),
                "attack_type": incident.get("attack_type"),
                "source_ip": incident.get("source_ip", "unknown"),
                "user": incident.get("user", "unknown"),
                "severity": incident.get("severity"),
            }
        }

        context.update(output)
        self.add_step(AGENT_ROLES["log_collection_agent"]["name"], incident, output)
        return context

    def detection_agent(self, context):
        attack_type = context["normalized_event"].get("attack_type", "unknown")

        output = {
            "detection": {
                "detected": True,
                "attack_type": attack_type,
                "rule_matched": f"{attack_type} detection rule",
            }
        }

        context.update(output)
        self.add_step(AGENT_ROLES["detection_agent"]["name"], context["normalized_event"], output)
        return context

    def mitre_attack_agent(self, context):
        attack_type = context["detection"]["attack_type"]

        mapping = {
            "sql injection": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            "brute force": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
            },
            "xss": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
        }

        output = {
            "mitre_mapping": mapping.get(
                attack_type,
                {
                    "technique_id": "Unknown",
                    "technique_name": "No mapping available",
                    "tactic": "Unknown",
                },
            )
        }

        context.update(output)
        self.add_step(AGENT_ROLES["mitre_attack_agent"]["name"], context["detection"], output)
        return context

    def threat_intelligence_agent(self, context):
        source_ip = context["normalized_event"].get("source_ip")

        reputation_db = {
            "103.22.55.9": {
                "country": "China",
                "reputation": "Malicious",
                "threat_score": 90,
            },
            "45.83.12.10": {
                "country": "Russia",
                "reputation": "Malicious",
                "threat_score": 95,
            },
        }

        output = {
            "threat_intelligence": reputation_db.get(
                source_ip,
                {
                    "country": "Unknown",
                    "reputation": "Unknown",
                    "threat_score": 0,
                },
            )
        }

        context.update(output)
        self.add_step(
            AGENT_ROLES["threat_intelligence_agent"]["name"],
            {"source_ip": source_ip},
            output,
        )
        return context

    def correlation_agent(self, context):
        event = context["normalized_event"]

        output = {
            "correlation": {
                "correlation_key": f"{event.get('attack_type')}|{event.get('source_ip')}|{event.get('user')}",
                "event_count": context["incident"].get("event_count", 1),
            }
        }

        context.update(output)
        self.add_step(
            AGENT_ROLES["correlation_agent"]["name"],
            event,
            output,
        )
        return context

    def severity_escalation_agent(self, context):
        event_count = context["correlation"]["event_count"]
        threat_score = context["threat_intelligence"]["threat_score"]

        if event_count >= 20 or threat_score >= 90:
            severity = "Critical"
            decision = "Escalate Immediately"
        elif event_count >= 10 or threat_score >= 70:
            severity = "High"
            decision = "Investigate Within 15 Minutes"
        else:
            severity = "Medium"
            decision = "Monitor"

        output = {
            "severity_escalation": {
                "severity": severity,
                "decision": decision,
                "reason": f"event_count={event_count}, threat_score={threat_score}",
            }
        }

        context.update(output)
        self.add_step(
            AGENT_ROLES["severity_escalation_agent"]["name"],
            {
                "event_count": event_count,
                "threat_score": threat_score,
            },
            output,
        )
        return context

    def case_management_agent(self, context):
        output = {
            "case_management": {
                "case_id": context["incident"].get("case_id"),
                "status": context["incident"].get("status", "Open"),
                "workflow_state": "Investigation Updated",
            }
        }

        context.update(output)
        self.add_step(
            AGENT_ROLES["case_management_agent"]["name"],
            context["severity_escalation"],
            output,
        )
        return context

    def investigation_agent(self, context):
        event = context["normalized_event"]
        severity = context["severity_escalation"]

        output = {
            "investigation_summary": {
                "summary": (
                    f"{event.get('attack_type')} detected from "
                    f"{event.get('source_ip')} affecting user {event.get('user')}. "
                    f"Severity is {severity['severity']} with decision: {severity['decision']}."
                ),
                "recommended_action": severity["decision"],
            }
        }

        context.update(output)
        self.add_step(
            AGENT_ROLES["investigation_agent"]["name"],
            context["case_management"],
            output,
        )
        return context


if __name__ == "__main__":
    sample_incident = {
        "case_id": "CASE-20260628070031",
        "attack_type": "sql injection",
        "source_ip": "103.22.55.9",
        "user": "guest",
        "severity": "Critical",
        "event_count": 26,
        "status": "In Progress",
    }

    orchestrator = MultiAgentOrchestrator()
    orchestrator.run(sample_incident)