class WindowsCollector:
    """
    Simulated Windows Event Log collector.

    Later we will replace this with real Windows Event Logs.
    """

    def collect_logs(self) -> list[str]:

        return [
            "2026-06-28 12:01:10 GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
            "2026-06-28 12:01:20 POST /login failed login source_ip=45.83.12.10 user=admin",
            "2026-06-28 12:01:30 GET /search?q=<script>alert(1)</script> source_ip=88.12.44.7 user=guest",
        ]


if __name__ == "__main__":

    collector = WindowsCollector()

    logs = collector.collect_logs()

    print("\n=== WINDOWS COLLECTOR TEST ===")

    for log in logs:
        print(log)