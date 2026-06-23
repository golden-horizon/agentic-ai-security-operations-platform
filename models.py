from pydantic import BaseModel
from typing import List


class IncidentReport(BaseModel):
    report_id: str
    user: str
    source_ip: str
    attack_type: str
    severity: str
    mitre: str
    reason: str
    recommended_actions: List[str]