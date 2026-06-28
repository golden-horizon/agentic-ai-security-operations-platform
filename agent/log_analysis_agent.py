import re

from mcp_tools.log_analysis_tools import analyze_logs
from mcp_tools.sigma_rule_engine import analyze_logs_with_sigma


class LogAnalysisAgent:
    """
    Converts raw security logs into SOC incidents.
    Uses the MCP-style log analysis tool.
    """

    def analyze(self, logs):
        return analyze_logs_with_sigma(logs)

    def findings_to_incidents(self, analysis_result: dict) -> list[dict]:
        incidents = []

        for finding in analysis_result["findings"]:
            log_line = finding["log_line"]

            source_ip = self.extract_value(log_line, "source_ip")
            user = self.extract_value(log_line, "user")
            request = self.extract_request(log_line)

            incidents.append(
                {
                    "attack_type": finding["attack_type"],
                    "source_ip": source_ip,
                    "user": user,
                    "request": request,
                    "raw_log": log_line,
                }
            )

        return incidents

    def extract_value(self, log_line: str, key: str) -> str:
        match = re.search(rf"{key}=([^\s]+)", log_line)

        if match:
            return match.group(1)

        return "unknown"

    def extract_request(self, log_line: str) -> str:
        match = re.search(r"(GET|POST)\s+(.+?)\s+source_ip=", log_line)

        if match:
            return match.group(2)

        return "unknown"


if __name__ == "__main__":
    agent = LogAnalysisAgent()

    sample_logs = [
        "2026-06-28 12:01:10 GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
        "2026-06-28 12:01:20 POST /login failed login source_ip=45.83.12.10 user=admin",
        "2026-06-28 12:01:30 GET /search?q=<script>alert(1)</script> source_ip=88.12.44.7 user=guest",
    ]

    analysis_result = agent.analyze(sample_logs)
    incidents = agent.findings_to_incidents(analysis_result)

    print("\n=== LOG ANALYSIS AGENT TEST ===")
    print(analysis_result)

    print("\n=== GENERATED INCIDENTS ===")
    print(incidents)