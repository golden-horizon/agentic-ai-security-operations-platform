class AWSCollector:
    """
    Simulated AWS log collector.

    Later this can be replaced with real boto3 integrations for:
    - CloudTrail
    - CloudWatch Logs
    - Lambda Logs
    - VPC Flow Logs
    """

    def collect_logs(self) -> list[str]:
        logs = []

        logs.extend(self.collect_cloudtrail_logs())
        logs.extend(self.collect_cloudwatch_logs())
        logs.extend(self.collect_lambda_logs())
        logs.extend(self.collect_vpc_flow_logs())

        return logs

    def collect_cloudtrail_logs(self) -> list[str]:
        return [
            "2026-06-28 12:05:10 AWS CloudTrail ConsoleLogin failed login source_ip=52.91.10.20 user=root",
            "2026-06-28 12:05:20 AWS CloudTrail AssumeRole suspicious api abuse source_ip=18.222.44.10 user=unknown",
        ]

    def collect_cloudwatch_logs(self) -> list[str]:
        return [
            "2026-06-28 12:06:10 AWS CloudWatch application failed login source_ip=45.83.12.10 user=admin",
        ]

    def collect_lambda_logs(self) -> list[str]:
        return [
            "2026-06-28 12:07:10 AWS Lambda GET /login?username=admin' OR '1'='1 source_ip=103.22.55.9 user=guest",
        ]

    def collect_vpc_flow_logs(self) -> list[str]:
        return [
            "2026-06-28 12:08:10 AWS VPCFlow suspicious connection source_ip=185.23.44.1 user=unknown",
        ]


if __name__ == "__main__":
    collector = AWSCollector()
    logs = collector.collect_logs()

    print("\n=== AWS COLLECTOR TEST ===")

    for log in logs:
        print(log)