from datetime import datetime
from db import conn

def calculate_risk(log, profile):

    risk = 0
    reasons = []
    cur = conn.cursor()

    # -------------------------
    # 1️⃣ Rule-Based Checks
    # -------------------------

    if log["resource"] not in profile["allowed_resources"]:
        risk += 40
        reasons.append("Unauthorized resource access")

    if log["action"] not in profile["allowed_actions"]:
        risk += 30
        reasons.append("Unauthorized action")

    if log["records_accessed"] > profile["max_records"]:
        risk += 30
        reasons.append("Excessive data access")

    # Use actual log timestamp if available
    hour = datetime.now().hour
    if hour < profile["normal_start_hour"] or hour > profile["normal_end_hour"]:
        risk += 20
        reasons.append("Access outside normal hours")

    # -------------------------
    # 2️⃣ User-Level Statistical Deviation
    # -------------------------

    cur.execute("""
        SELECT AVG(records_accessed), STDDEV(records_accessed)
        FROM activity_logs
        WHERE user_id = %s
    """, (log["user_id"],))

    result = cur.fetchone()

    user_avg = result[0] or 0
    user_std = result[1] or 0

    if user_std and user_std > 0:
        z_score = abs(log["records_accessed"] - user_avg) / user_std

        if z_score > 2:  # statistically significant deviation
            risk += 25
            reasons.append("Unusual data access pattern (User deviation)")

    # -------------------------
    # 3️⃣ Burst Detection
    # -------------------------

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE user_id = %s
        AND created_at > NOW() - INTERVAL '5 minutes'
    """, (log["user_id"],))

    burst_count = cur.fetchone()[0]

    if burst_count > 5:
        risk += 25
        reasons.append("Burst access detected")

    cur.close()

    return risk, reasons
