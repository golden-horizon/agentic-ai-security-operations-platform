from intelligence.kev_checker import check_cve_in_kev
from intelligence.ip_reputation import check_ip_reputation
from intelligence.cve_lookup import check_cve


def calculate_risk_score(ip_result, cve_result, kev_result, incident):
    score = 0

    # IP Reputation
    if ip_result.get("reputation") == "malicious":
        score += 35
    elif ip_result.get("reputation") == "suspicious":
        score += 20

    # Attack Pattern
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

    # CVE Severity
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


def detect_possible_zero_day(cve_result, kev_result, risk_score, incident):
    request = incident.get("request", "").lower()

    known_attack_patterns = [
        "' or '1'='1",
        "union select",
        "<script>",
        "failed_attempts",
    ]

    known_pattern_detected = any(
        pattern in request for pattern in known_attack_patterns
    )

    return (
        not known_pattern_detected
        and not cve_result.get("found")
        and not kev_result.get("found")
        and risk_score >= 70
    )


def build_intelligence_package(incident):
    source_ip = incident.get("source_ip", "unknown")
    cve_id = incident.get("cve_id")
    product_name = incident.get("product")

    ip_result = check_ip_reputation(source_ip)

    if cve_id:
        cve_result = check_cve(cve_id)
        kev_result = check_cve_in_kev(cve_id)
    elif product_name:
        cve_result = check_cve(product_name)

        if cve_result.get("found"):
            kev_result = check_cve_in_kev(cve_result.get("cve_id"))
        else:
            kev_result = {
                "found": False,
                "message": "No CVE linked to this incident",
            }
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

    possible_zero_day = detect_possible_zero_day(
        cve_result,
        kev_result,
        risk_score,
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
        "possible_zero_day": possible_zero_day,
        "zero_day_note": (
            "Possible zero-day or untracked exploit behavior. "
            "No CVE or CISA KEV match was found, but risk remains high."
            if possible_zero_day
            else "No zero-day indicator based on current evidence."
        ),
    }

if __name__ == "__main__":
    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "product": "log4j",
        "request": "/login?username=admin' OR '1'='1",
    }

    package = build_intelligence_package(test_incident)

    print("\n=== INTELLIGENCE PACKAGE ===")
    print(package)