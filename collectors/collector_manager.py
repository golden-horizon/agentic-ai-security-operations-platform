from collectors.windows_collector import WindowsCollector
from collectors.aws_collector import AWSCollector
from collectors.azure_collector import AzureCollector
from collectors.splunk_collector import SplunkCollector
from collectors.linux_collector import LinuxCollector

class CollectorManager:
    """
    Central collector orchestrator.
    """

    def __init__(self):
        self.collectors = [
           WindowsCollector(),
           AWSCollector(),
           AzureCollector(),
           SplunkCollector(),
           LinuxCollector(),
        ]     

    def collect_logs(self) -> list[str]:

        all_logs = []

        for collector in self.collectors:
            logs = collector.collect_logs()
            all_logs.extend(logs)

        return all_logs


if __name__ == "__main__":

    manager = CollectorManager()

    logs = manager.collect_logs()

    print("\n=== COLLECTOR MANAGER TEST ===")

    for log in logs:
        print(log)