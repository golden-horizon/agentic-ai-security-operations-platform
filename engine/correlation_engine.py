class CorrelationEngine:
    """
    Finds whether a new incident matches an existing open case.
    """

    @staticmethod
    def build_correlation_key(incident: dict) -> str:
        attack_type = incident.get("attack_type", "unknown").lower()
        source_ip = incident.get("source_ip", "unknown").lower()
        user = incident.get("user", "unknown").lower()

        return f"{attack_type}|{source_ip}|{user}"

    @staticmethod
    def find_matching_case(incident: dict, cases: list[dict]) -> dict | None:
        new_key = CorrelationEngine.build_correlation_key(incident)

        for case in cases:
            if case.get("status") not in ["Open", "Reopened"]:
                continue

            existing_incident = case.get("incident", {})
            existing_key = CorrelationEngine.build_correlation_key(existing_incident)

            if existing_key == new_key:
                return case

        return None