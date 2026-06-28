SUSPICIOUS_PATTERNS = {
    "sql injection": [
        "' OR '1'='1",
        "union select",
        "drop table",
    ],
    "xss": [
        "<script>",
        "javascript:",
        "onerror=",
    ],
    "brute force": [
        "failed login",
        "invalid password",
        "authentication failed",
    ],
}


def analyze_logs(log_lines: list[str]) -> dict:
    findings = []

    for line in log_lines:
        line_lower = line.lower()

        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in line_lower:
                    findings.append(
                        {
                            "attack_type": attack_type,
                            "matched_pattern": pattern,
                            "log_line": line,
                        }
                    )

    return {
        "finding_count": len(findings),
        "findings": findings,
        "suspicious": len(findings) > 0,
    }


if __name__ == "__main__":
    sample_logs = [
        "2026-06-28 12:01:10 GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
        "2026-06-28 12:01:20 POST /login failed login source_ip=45.83.12.10 user=admin",
        "2026-06-28 12:01:30 GET /search?q=<script>alert(1)</script> source_ip=88.12.44.7 user=guest",
    ]

    result = analyze_logs(sample_logs)

    print("\n=== LOG ANALYSIS TEST ===")
    print(result)