import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev_catalog():
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def check_cve_in_kev(cve_id: str):
    catalog = load_kev_catalog()
    vulnerabilities = catalog.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        if vuln.get("cveID", "").upper() == cve_id.upper():
            return {
                "found": True,
                "cve_id": vuln.get("cveID"),
                "vendor": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "vulnerability_name": vuln.get("vulnerabilityName"),
                "date_added": vuln.get("dateAdded"),
                "required_action": vuln.get("requiredAction"),
                "due_date": vuln.get("dueDate"),
                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
            }

    return {
        "found": False,
        "cve_id": cve_id,
        "message": "CVE not found in CISA KEV catalog",
    }


if __name__ == "__main__":
    test_cve = "CVE-2021-44228"
    result = check_cve_in_kev(test_cve)

    print("\n=== CISA KEV CHECK RESULT ===")
    print(result)