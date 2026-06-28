import json
from pathlib import Path


RULE_FILE = Path("rules/sigma_rules.json")


def load_sigma_rules() -> list[dict]:
    return json.loads(RULE_FILE.read_text())


def match_sigma_rules(log_line: str) -> list[dict]:
    rules = load_sigma_rules()
    matches = []
    log_lower = log_line.lower()

    for rule in rules:
        for pattern in rule["patterns"]:
            if pattern.lower() in log_lower:
                matches.append(
                    {
                        "rule_title": rule["title"],
                        "attack_type": rule["attack_type"],
                        "mitre_id": rule["mitre_id"],
                        "severity": rule["severity"],
                        "matched_pattern": pattern,
                        "log_line": log_line,
                    }
                )
                break

    return matches


def analyze_logs_with_sigma(log_lines: list[str]) -> dict:
    findings = []

    for line in log_lines:
        findings.extend(match_sigma_rules(line))

    return {
        "finding_count": len(findings),
        "findings": findings,
        "suspicious": len(findings) > 0,
    }


if __name__ == "__main__":
    sample_logs = [
        "2026-06-28 12:01:10 GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
        "2026-06-28 12:05:20 AWS CloudTrail AssumeRole suspicious api abuse source_ip=18.222.44.10 user=unknown",
        "2026-06-28 12:08:10 AWS VPCFlow suspicious connection source_ip=185.23.44.1 user=unknown",
    ]

    result = analyze_logs_with_sigma(sample_logs)

    print("\n=== SIGMA RULE ENGINE TEST ===")
    print(result)