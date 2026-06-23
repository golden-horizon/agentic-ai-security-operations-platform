def build_result(attack_type, severity, mitre, reason, actions):
    return {
        "attack_type": attack_type,
        "severity": severity,
        "mitre": mitre,
        "reason": reason,
        "recommended_actions": actions
    }


def analyze_incident(incident):
    text = str(incident).lower()
    failed_attempts = incident.get("failed_attempts", 0)

    # Brute Force Detection
    if failed_attempts >= 5:
        return build_result(
            "Brute Force",
            "High",
            "T1110 - Brute Force",
            "Multiple failed login attempts detected.",
            [
                "Block source IP",
                "Reset password",
                "Check successful logins",
                "Enable MFA"
            ]
        )

    # SQL Injection Detection
    if (
        "select" in text
        or "union" in text
        or "' or '1'='1" in text
        or "drop table" in text
    ):
        return build_result(
            "SQL Injection",
            "Critical",
            "T1190 - Exploit Public-Facing Application",
            "Suspicious SQL keywords detected in request.",
            [
                "Block source IP",
                "Review web logs",
                "Validate input",
                "Use parameterized queries"
            ]
        )

    # XSS Detection
    if (
        "<script>" in text
        or "javascript:" in text
        or "onerror=" in text
    ):
        return build_result(
            "XSS",
            "High",
            "T1059 - Command and Scripting Interpreter",
            "Possible script injection detected.",
            [
                "Sanitize input",
                "Apply output encoding",
                "Review affected page",
                "Add CSP headers"
            ]
        )

    # API Abuse Detection
    if incident.get("request_count", 0) > 100:
        return build_result(
            "API Abuse",
            "High",
            "T1499 - Endpoint Denial of Service",
            "Unusually high number of API requests detected.",
            [
                "Rate-limit source IP",
                "Review API logs",
                "Check API key usage",
                "Block suspicious source"
            ]
        )

    # Session Hijacking Detection
    if (
        "session_token_changed" in text
        or "impossible travel" in text
        or incident.get("session_anomaly", False)
    ):
        return build_result(
            "Session Hijacking",
            "Critical",
            "T1550 - Use Alternate Authentication Material",
            "Suspicious session activity detected.",
            [
                "Invalidate session",
                "Force password reset",
                "Enable MFA",
                "Review login history"
            ]
        )

    # Unknown Event
    return build_result(
        "Unknown",
        "Low",
        "N/A",
        "No clear attack pattern detected.",
        [
            "Monitor activity"
        ]
    )