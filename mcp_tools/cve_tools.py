CVE_DATABASE = {
    "log4j": {
        "found": True,
        "cve_id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "description": "Apache Log4j remote code execution vulnerability.",
    },
    "apache struts": {
        "found": True,
        "cve_id": "CVE-2017-5638",
        "severity": "CRITICAL",
        "description": "Apache Struts remote code execution vulnerability.",
    },
    "exchange": {
        "found": True,
        "cve_id": "CVE-2021-26855",
        "severity": "CRITICAL",
        "description": "Microsoft Exchange Server SSRF vulnerability.",
    },
}


def lookup_cve(product_name: str | None) -> dict:
    if not product_name:
        return {
            "found": False,
            "message": "No product name provided",
        }

    product = product_name.lower()

    return CVE_DATABASE.get(
        product,
        {
            "found": False,
            "message": "No CVE linked to this incident",
        },
    )


if __name__ == "__main__":
    result = lookup_cve("log4j")

    print("\n=== CVE LOOKUP TEST ===")
    print(result)