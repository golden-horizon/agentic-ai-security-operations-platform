import json
from difflib import SequenceMatcher
from pathlib import Path
from mitreattack.stix20 import MitreAttackData


ATTACK_JSON_FILE = "enterprise-attack.json"


def get_mitre_id(technique: dict) -> str:
    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "Unknown")
    return "Unknown"


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def load_techniques():
    if not Path(ATTACK_JSON_FILE).exists():
        raise FileNotFoundError("enterprise-attack.json not found. Run mitre_lookup.py first.")

    attack_data = MitreAttackData(ATTACK_JSON_FILE)
    return attack_data.get_techniques(remove_revoked_deprecated=True)


def search_mitre(query: str, limit: int = 5):
    techniques = load_techniques()
    query_lower = query.lower()
    results = []

    for technique in techniques:
        name = technique.get("name", "")
        description = technique.get("description", "")
        mitre_id = get_mitre_id(technique)

        score = 0

        if name.lower() == query_lower:
            score += 100

        if query_lower in name.lower():
            score += 70

        if query_lower in description.lower():
            score += 20

        score += similarity(query, name) * 30

        if score > 0:
            results.append({
                "id": mitre_id,
                "name": name,
                "score": round(score, 2),
                "description": description[:350]
            })

    results.sort(key=lambda item: item["score"], reverse=True)
    return results[:limit]


def main():
    while True:
        query = input("\nSearch MITRE technique, or type exit: ")

        if query.lower() == "exit":
            break

        results = search_mitre(query)

        if not results:
            print("No results found.")
            continue

        for item in results:
            print("\n--------------------")
            print(f"Score: {item['score']}")
            print(f"ID: {item['id']}")
            print(f"Name: {item['name']}")
            print(f"Description: {item['description']}...")


if __name__ == "__main__":
    main()