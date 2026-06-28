class LinuxCollector:
    """
    Simulated Linux / Syslog collector.

    Later this can collect from:
    - /var/log/auth.log
    - /var/log/syslog
    - rsyslog
    - journald
    """

    def collect_logs(self) -> list[str]:
        return [
            "2026-06-28 12:20:10 Linux sshd failed login source_ip=45.83.12.10 user=root",
            "2026-06-28 12:20:20 Linux sudo privilege escalation source_ip=10.0.1.25 user=webapp",
            "2026-06-28 12:20:30 Linux outbound suspicious connection source_ip=10.0.1.50 user=unknown",
        ]


if __name__ == "__main__":
    collector = LinuxCollector()

    print("\n=== LINUX COLLECTOR TEST ===")

    for log in collector.collect_logs():
        print(log)