from agent.soc_analyzer import analyze_incident
from intelligence.mitre_search import search_mitre


def search_mitre_tool(query: str) -> dict:
    results = search_mitre(query, limit=3)

    return {
        "query": query,
        "results": results
    }


def analyze_incident_tool(incident: dict) -> dict:
    return analyze_incident(incident)


def generate_summary_tool(reports: list) -> dict:
    total = len(reports)
    critical = 0
    high = 0

    for report in reports:
        mitre = report.get("selected_mitre", {})
        analysis = report.get("analysis", "").lower()

        if "critical" in analysis:
            critical += 1
        elif "high" in analysis:
            high += 1

    return {
        "total_reports": total,
        "critical_or_likely_critical": critical,
        "high_or_likely_high": high
    }