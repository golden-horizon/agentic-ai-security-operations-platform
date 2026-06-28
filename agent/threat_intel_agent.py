from intelligence.intelligence_manager import build_intelligence_package


class ThreatIntelAgent:
    """
    Structured threat intelligence agent.
    Uses Intelligence Manager and returns facts, not paragraphs.
    """

    def analyze_threat_intel(self, incident: dict) -> dict:
        intelligence_package = build_intelligence_package(incident)

        evidence = intelligence_package["evidence"]
        ip_reputation = evidence["ip_reputation"]
        cve_lookup = evidence["cve_lookup"]
        cisa_kev = evidence["cisa_kev"]

        return {
            "intelligence_package": intelligence_package,
            "summary": {
                "risk_score": intelligence_package["risk_score"],
                "priority": intelligence_package["priority"],
                "possible_zero_day": intelligence_package["possible_zero_day"],
                "zero_day_note": intelligence_package["zero_day_note"],
                "source_ip": ip_reputation.get("ip", "Not observed"),
                "ip_reputation": ip_reputation.get("reputation", "unknown"),
                "ip_confidence": ip_reputation.get("confidence", 0),
                "ip_reason": ip_reputation.get("reason", "Not observed"),
                "cve_found": cve_lookup.get("found", False),
                "cve_id": cve_lookup.get("cve_id", "Not observed"),
                "cve_severity": cve_lookup.get("severity", "Not observed"),
                "kev_found": cisa_kev.get("found", False),
                "known_ransomware_use": cisa_kev.get(
                    "known_ransomware_use",
                    "Not observed",
                ),
            },
        }


if __name__ == "__main__":
    agent = ThreatIntelAgent()

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    result = agent.analyze_threat_intel(test_incident)

    print("\n=== THREAT INTEL AGENT TEST ===")
    print(result)