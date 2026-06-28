class SplunkCollector:
    """
    Simulated Splunk collector.

    Later this can connect to:
    - Splunk Enterprise
    - Splunk Cloud
    - Splunk REST API
    """

    def collect_logs(self) -> list[str]:
        return [
            "2026-06-28 12:15:10 Splunk notable event failed login source_ip=203.0.113.10 user=admin",
            "2026-06-28 12:15:20 Splunk correlation search privilege escalation source_ip=198.51.100.22 user=service_account",
            "2026-06-28 12:15:30 Splunk notable event suspicious connection source_ip=192.0.2.44 user=unknown",
        ]


if __name__ == "__main__":
    collector = SplunkCollector()

    print("\n=== SPLUNK COLLECTOR TEST ===")

    for log in collector.collect_logs():
        print(log)