from datetime import datetime, timezone
from typing import Any


class InvestigationCase:
    """
    Structured investigation case object.

    This keeps facts, analysis, recommendations, and decisions separate
    so the LLM does not mix them together.
    """

    def __init__(self, incident: dict[str, Any]):
        self.case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.status = "Open"

        self.incident = incident
        self.iocs = {}
        self.mitre_analysis = ""
        self.threat_intelligence = {}
        self.remediation = ""
        self.soc_decision = ""
        self.executive_summary = ""
        self.timeline = []

    def add_timeline_event(self, event: str) -> None:
      self.timeline.append(
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "status": self.status,
            "incident": self.incident,
            "iocs": self.iocs,
            "mitre_analysis": self.mitre_analysis,
            "threat_intelligence": self.threat_intelligence,
            "remediation": self.remediation,
            "soc_decision": self.soc_decision,
            "executive_summary": self.executive_summary,
            "timeline": self.timeline,
        }


if __name__ == "__main__":
    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    case = InvestigationCase(test_incident)

    print("\n=== CASE TEST ===")
    print(case.to_dict())