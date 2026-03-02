import psycopg2
from db import conn

def build_role_profiles():

    cur = conn.cursor()

    # 1️⃣ Compute average and std deviation per role
    cur.execute("""
        SELECT u.role_id,
            AVG(l.records_accessed) AS avg_records,
            STDDEV(l.records_accessed) AS std_records,
            MIN(EXTRACT(HOUR FROM l.created_at)) AS start_hour,
            MAX(EXTRACT(HOUR FROM l.created_at)) AS end_hour
        FROM activity_logs l
        JOIN users u ON l.user_id = u.user_id
        GROUP BY u.role_id
    """)

    results = cur.fetchall()

    for row in results:
        role_id = row[0]
        avg_records = float(row[1]) if row[1] is not None else 0.0
        std_records = float(row[2]) if row[2] is not None else 0.0
        start_hour = int(row[3]) if row[3] is not None else 9
        end_hour = int(row[4]) if row[4] is not None else 18

        # Update role_behavior_profiles
        cur.execute("""
            UPDATE role_behavior_profiles
            SET avg_records = %s,
                std_records = %s,
                normal_start_hour = %s,
                normal_end_hour = %s,
                max_records = %s
            WHERE role_id = %s
        """, (
            avg_records,
            std_records,
            start_hour,
            end_hour,
            int(avg_records * 1.5),  # dynamic threshold
            role_id
        ))

    conn.commit()
    cur.close()

    print("✅ Role behavior profiles updated.")