from agent.log_analysis_agent import LogAnalysisAgent
from agent.soc_manager_agent import SOCManagerAgent


def main():
    sample_logs = [
        "2026-06-28 12:01:10 GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
        "2026-06-28 12:01:20 POST /login failed login source_ip=45.83.12.10 user=admin",
        "2026-06-28 12:01:30 GET /search?q=<script>alert(1)</script> source_ip=88.12.44.7 user=guest",
    ]

    log_agent = LogAnalysisAgent()
    soc_manager = SOCManagerAgent()

    analysis_result = log_agent.analyze(sample_logs)
    incidents = log_agent.findings_to_incidents(analysis_result)

    print("\n=== LOG FINDINGS ===")
    print(f"Findings detected: {analysis_result['finding_count']}")

    print("\n=== GENERATED INCIDENTS ===")
    for index, incident in enumerate(incidents, start=1):
        print(f"{index}. {incident['attack_type']} from {incident['source_ip']}")

    print("\n=== INVESTIGATING INCIDENTS ===")

    for index, incident in enumerate(incidents, start=1):

        print(f"\n{'=' * 60}")
        print(f"INCIDENT {index}")
        print(f"{'=' * 60}")

        investigation = soc_manager.investigate(incident)

        print(f"Attack Type : {incident['attack_type']}")
        print(f"Source IP   : {incident['source_ip']}")
        print(f"User        : {incident['user']}")

        print(f"\nCase ID     : {investigation['case_id']}")
        print(f"Decision    : {investigation['soc_decision']}")


if __name__ == "__main__":
    main()