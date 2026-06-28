class DecisionEngine:
    """
    Deterministic SOC decision engine.
    Uses rules instead of AI for final escalation decisions.
    """

    @staticmethod
    def make_decision(
        risk_score: int,
        priority: str,
        possible_zero_day: bool,
        kev_found: bool,
        attack_type: str = "",
    ):

        attack_type = attack_type.lower()

        if possible_zero_day:
            return "Escalate Immediately"

        if kev_found:
            return "Escalate Immediately"

        if risk_score >= 80:
            return "Escalate Immediately"

        if attack_type in [
         "sql injection",
         "brute force",
         "xss",
         "api abuse",
         "network anomaly",
         "impossible travel",
         "privilege escalation",
        ]:
            return "Investigate Within 15 Minutes"

        if risk_score >= 60:
            return "Investigate Within 15 Minutes"

        return "Monitor"


if __name__ == "__main__":

    decision = DecisionEngine.make_decision(
        risk_score=35,
        priority="Medium",
        possible_zero_day=False,
        kev_found=False,
        attack_type="brute force",
    )

    print("\n=== DECISION ENGINE TEST ===")
    print(decision)