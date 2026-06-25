from mitreattack.stix20 import MitreAttackData
import urllib.request
from pathlib import Path


ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_JSON_FILE = "enterprise-attack.json"


def download_attack_data():
    if Path(ATTACK_JSON_FILE).exists():
        print("MITRE ATT&CK data already exists.")
        return

    print("Downloading MITRE ATT&CK Enterprise data...")
    urllib.request.urlretrieve(ATTACK_JSON_URL, ATTACK_JSON_FILE)
    print("Download complete.")


def search_techniques(keyword: str, limit: int = 5):
    attack_data = MitreAttackData(ATTACK_JSON_FILE)
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

    results = []

    for technique in techniques:
        name = technique.get("name", "")
        description = technique.get("description", "")

        text = f"{name} {description}".lower()

        if keyword.lower() in text:
            external_id = "Unknown"

            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "Unknown")

            results.append({
                "id": external_id,
                "name": name,
                "description": description[:300]
            })

    return results[:limit]


def main():
    download_attack_data()

    while True:
        query = input("\nSearch MITRE technique, or type exit: ")

        if query.lower() == "exit":
            break

        results = search_techniques(query)

        if not results:
            print("No matching techniques found.")
            continue

        for item in results:
            print("\n--------------------")
            print(f"ID: {item['id']}")
            print(f"Name: {item['name']}")
            print(f"Description: {item['description']}...")


if __name__ == "__main__":
    main()