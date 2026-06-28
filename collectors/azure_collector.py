class AzureCollector:
    """
    Simulated Azure log collector.

    Later this can be replaced with real Microsoft Graph / Azure Monitor / Sentinel APIs.
    """

    def collect_logs(self) -> list[str]:
        logs = []

        logs.extend(self.collect_signin_logs())
        logs.extend(self.collect_audit_logs())
        logs.extend(self.collect_defender_logs())

        return logs

    def collect_signin_logs(self) -> list[str]:
        return [
            "2026-06-28 12:10:10 Azure EntraID failed login source_ip=40.90.12.10 user=admin@company.com",
            "2026-06-28 12:10:20 Azure EntraID impossible travel source_ip=20.55.44.9 user=user@company.com",
        ]

    def collect_audit_logs(self) -> list[str]:
        return [
            "2026-06-28 12:11:10 Azure AuditLog privilege escalation source_ip=51.144.22.8 user=unknown",
        ]

    def collect_defender_logs(self) -> list[str]:
        return [
            "2026-06-28 12:12:10 Azure Defender suspicious connection source_ip=13.75.91.4 user=vm_admin",
        ]


if __name__ == "__main__":
    collector = AzureCollector()
    logs = collector.collect_logs()

    print("\n=== AZURE COLLECTOR TEST ===")

    for log in logs:
        print(log)