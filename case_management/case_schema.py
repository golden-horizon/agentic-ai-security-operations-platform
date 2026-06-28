from typing import TypedDict


class MITREAnalysis(TypedDict):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    explanation: str


class ThreatIntelSummary(TypedDict):
    risk_score: int
    priority: str
    possible_zero_day: bool
    ip_reputation: str
    cve_found: bool
    kev_found: bool


class RemediationPlan(TypedDict):
    immediate_actions: list[str]
    investigation_actions: list[str]
    remediation_actions: list[str]
    recovery_actions: list[str]
    prevention_actions: list[str]
    owner_teams: list[str]


class SOCDecision(TypedDict):
    decision: str
    reason: str
    confidence: str