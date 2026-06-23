from tools import analyze_incident


def map_attack(incident):
    result = analyze_incident(incident)
    return result["attack_type"]


def map_mitre(incident):
    result = analyze_incident(incident)
    return result["mitre"]


def recommend_actions(incident):
    result = analyze_incident(incident)
    return result["recommended_actions"]


def calculate_severity(incident):
    result = analyze_incident(incident)
    return result["severity"]