from mcp_tools.cve_tools import lookup_cve


def check_cve(product_name: str | None) -> dict:
    return lookup_cve(product_name)


if __name__ == "__main__":
    result = check_cve("log4j")

    print("\n=== CVE CHECK TEST ===")
    print(result)