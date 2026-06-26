import requests

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id: str):
    try:
        response = requests.get(
            NVD_CVE_API,
            params={"cveId": cve_id},
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "found": False,
                "cve_id": cve_id,
                "message": "CVE not found in NVD",
            }

        cve = vulnerabilities[0]["cve"]

        description = "No English description found"
        for item in cve.get("descriptions", []):
            if item.get("lang") == "en":
                description = item.get("value")
                break

        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None

        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            cvss_score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]
            cvss_score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            cvss_score = metric["cvssData"]["baseScore"]
            severity = metric.get("baseSeverity")

        return {
            "found": True,
            "cve_id": cve_id,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "source": "NVD",
        }

    except requests.RequestException as error:
        return {
            "found": False,
            "cve_id": cve_id,
            "error": str(error),
            "source": "NVD",
            "message": "NVD lookup failed, continuing with available evidence",
        }


if __name__ == "__main__":
    result = lookup_cve("CVE-2021-44228")
    print("\n=== CVE LOOKUP RESULT ===")
    print(result)