KNOWN_BAD_IPS = {
    "45.83.12.10": {
        "reputation": "malicious",
        "confidence": 85,
        "reason": "Known brute-force source in sample threat intel"
    },
    "103.22.55.9": {
        "reputation": "malicious",
        "confidence": 95,
        "reason": "Known web attack source in sample threat intel"
    },
    "88.12.44.7": {
        "reputation": "suspicious",
        "confidence": 70,
        "reason": "Observed XSS probing behavior"
    },
    "91.77.10.5": {
        "reputation": "suspicious",
        "confidence": 75,
        "reason": "High-volume API abuse pattern"
    },
    "22.44.66.88": {
        "reputation": "malicious",
        "confidence": 90,
        "reason": "Session anomaly and impossible travel indicator"
    },
}


def check_ip_reputation(ip_address: str):
    if ip_address in KNOWN_BAD_IPS:
        return {
            "found": True,
            "ip": ip_address,
            **KNOWN_BAD_IPS[ip_address],
        }

    return {
        "found": False,
        "ip": ip_address,
        "reputation": "unknown",
        "confidence": 0,
        "reason": "No reputation data found"
    }


if __name__ == "__main__":
    test_ip = "103.22.55.9"
    result = check_ip_reputation(test_ip)

    print("\n=== IP REPUTATION RESULT ===")
    print(result)