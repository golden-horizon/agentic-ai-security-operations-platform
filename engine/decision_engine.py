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
    ):

        if possible_zero_day:
            return "Escalate Immediately"

        if kev_found:
            return "Escalate Immediately"

        if risk_score >= 80:
            return "Escalate Immediately"

        if risk_score >= 60:
            return "Investigate Within 15 Minutes"

        return "Monitor"


if __name__ == "__main__":

    decision = DecisionEngine.make_decision(
        risk_score=70,
        priority="High",
        possible_zero_day=False,
        kev_found=False,
    )

    print("\n=== DECISION ENGINE TEST ===")
    print(decision)