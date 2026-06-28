import json
from pathlib import Path

from agent.log_analysis_agent import LogAnalysisAgent
from agent.soc_manager_agent import SOCManagerAgent
from collectors.windows_collector import WindowsCollector


def main():
    collector = WindowsCollector()
    sample_logs = collector.collect_logs()

    log_agent = LogAnalysisAgent()
    soc_manager = SOCManagerAgent()

    analysis_result = log_agent.analyze(sample_logs)
    incidents = log_agent.findings_to_incidents(analysis_result)

    investigations = []

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
        investigations.append(investigation)

        print(f"Attack Type : {incident['attack_type']}")
        print(f"Source IP   : {incident['source_ip']}")
        print(f"User        : {incident['user']}")

        print(f"\nCase ID     : {investigation['case_id']}")
        print(f"Decision    : {investigation['soc_decision']}")

    output_file = Path("reports/log_pipeline_cases.json")
    output_file.parent.mkdir(exist_ok=True)

    output_file.write_text(
        json.dumps(investigations, indent=2)
    )

    print("\n=== REPORT SAVED ===")
    print(output_file)


if __name__ == "__main__":
    main()