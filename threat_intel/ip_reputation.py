import json
from pathlib import Path


class IPReputation:

    def __init__(self):
        feed_file = Path("threat_intel/threat_feed.json")

        with open(feed_file, "r") as file:
            self.feed = json.load(file)

    def lookup(self, ip_address: str) -> dict:

        return self.feed.get(
            ip_address,
            {
                "country": "Unknown",
                "reputation": "Unknown",
                "threat_score": 0
            }
        )


if __name__ == "__main__":

    intel = IPReputation()

    print("\n=== THREAT INTEL TEST ===")

    print(intel.lookup("45.83.12.10"))
    print(intel.lookup("8.8.8.8"))