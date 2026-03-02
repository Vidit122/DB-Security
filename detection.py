from datetime import datetime

def calculate_risk(log, profile):
    risk = 0
    reasons = []

    # Resource check
    if log["resource"] not in profile["allowed_resources"]:
        risk += 40
        reasons.append("Unauthorized resource access")

    # Action check
    if log["action"] not in profile["allowed_actions"]:
        risk += 30
        reasons.append("Unauthorized action")

    # Volume check
    if log["records_accessed"] > profile["max_records"]:
        risk += 30
        reasons.append("Excessive data access")

    # Time check
    hour = datetime.now().hour
    if hour < profile["start_hour"] or hour > profile["end_hour"]:
        risk += 20
        reasons.append("Access outside normal hours")

    return risk, reasons
