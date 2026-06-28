class FirewallCollector:
    """
    Simulated firewall log collector.

    Later this can connect to:
    - Palo Alto
    - Fortinet
    - Cisco ASA
    - pfSense
    - Sophos
    """

    def collect_logs(self) -> list[str]:
        return [
            "2026-06-28 12:25:10 Firewall blocked connection source_ip=185.200.10.1 user=unknown",
            "2026-06-28 12:25:20 Firewall port scan detected source_ip=103.44.22.1 user=unknown",
            "2026-06-28 12:25:30 Firewall suspicious outbound connection source_ip=10.0.1.50 user=server01",
        ]


if __name__ == "__main__":
    collector = FirewallCollector()

    print("\n=== FIREWALL COLLECTOR TEST ===")

    for log in collector.collect_logs():
        print(log)