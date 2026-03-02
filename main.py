from fastapi import FastAPI, HTTPException
from models import ActivityLog
from db import get_cursor, conn
from role_behavior import build_role_profiles

from detection import calculate_risk
build_role_profiles()
app = FastAPI(title="SECaaS Insider Threat Detection Backend")


@app.post("/logActivity")
def log_activity(log: ActivityLog):
    cur = get_cursor()

    # 1️⃣ Insert activity log
    cur.execute("""
        INSERT INTO activity_logs
        (user_id, action, resource, records_accessed, ip_address)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        log.user_id,
        log.action,
        log.resource,
        log.records_accessed,
        log.ip_address
    ))

    # 2️⃣ Fetch role behavior profile
    cur.execute("""
        SELECT rb.max_records,
               rb.allowed_actions,
               rb.allowed_resources,
               rb.normal_start_hour,
               rb.normal_end_hour
        FROM role_behavior_profiles rb
        JOIN users u ON rb.role_id = u.role_id
        WHERE u.user_id = %s
    """, (log.user_id,))

    row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="User or role profile not found")

    profile = {
        "max_records": row[0],
        "allowed_actions": row[1],
        "allowed_resources": row[2],
        "normal_start_hour": row[3],
        "normal_end_hour": row[4]
    }

    # 3️⃣ Risk calculation
    risk, reasons = calculate_risk(log.dict(), profile)

    # 4️⃣ Alert decision
    severity = "GREEN"
    if risk >= 60:
        severity = "HIGH"
    elif risk >= 30:
        severity = "MEDIUM"

    if severity != "GREEN":
        cur.execute("""
            INSERT INTO alerts
            (user_id, risk_score, severity, reason)
            VALUES (%s, %s, %s, %s)
        """, (
            log.user_id,
            risk,
            severity,
            ", ".join(reasons)
        ))

    conn.commit()

    return {
        "status": "logged",
        "risk_score": risk,
        "severity": severity,
        "reasons": reasons
    }

