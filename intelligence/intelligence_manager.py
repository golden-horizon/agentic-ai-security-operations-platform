from intelligence.cve_lookup import lookup_cve
from intelligence.kev_checker import check_cve_in_kev
from intelligence.ip_reputation import check_ip_reputation


def calculate_risk_score(ip_result, cve_result, kev_result, incident):
    score = 0

    # IP Reputation
    if ip_result.get("reputation") == "malicious":
        score += 35
    elif ip_result.get("reputation") == "suspicious":
        score += 20

    # Attack Type
    request = incident.get("request", "").lower()

    if "' or '1'='1" in request or "union select" in request:
        score += 35

    elif "<script>" in request:
        score += 25

    elif incident.get("failed_attempts", 0) >= 5:
        score += 20

    elif incident.get("request_count", 0) >= 200:
        score += 20

    elif incident.get("session_anomaly"):
        score += 30

    # CVE
    if cve_result.get("severity") == "CRITICAL":
        score += 35
    elif cve_result.get("severity") == "HIGH":
        score += 25

    # CISA KEV
    if kev_result.get("found"):
        score += 25

    if kev_result.get("known_ransomware_use") == "Known":
        score += 5

    return min(score, 100)


def get_priority(risk_score):
    if risk_score >= 80:
        return "Critical"
    if risk_score >= 60:
        return "High"
    if risk_score >= 30:
        return "Medium"
    return "Low"


def build_intelligence_package(incident):
    source_ip = incident.get("source_ip", "unknown")
    cve_id = incident.get("cve_id")

    ip_result = check_ip_reputation(source_ip)

    if cve_id:
        cve_result = lookup_cve(cve_id)
        kev_result = check_cve_in_kev(cve_id)
    else:
        cve_result = {
            "found": False,
            "message": "No CVE linked to this incident",
        }
        kev_result = {
            "found": False,
            "message": "No CVE linked to this incident",
        }

    risk_score = calculate_risk_score(
    ip_result,
    cve_result,
    kev_result,
    incident,
)

    return {
        "incident": incident,
        "evidence": {
            "ip_reputation": ip_result,
            "cve_lookup": cve_result,
            "cisa_kev": kev_result,
        },
        "risk_score": risk_score,
        "priority": get_priority(risk_score),
    }


if __name__ == "__main__":
    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    package = build_intelligence_package(test_incident)

    print("\n=== INTELLIGENCE PACKAGE ===")
    print(package)