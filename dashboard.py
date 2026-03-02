import streamlit as st
import pandas as pd
import psycopg2
import os
from dotenv import load_dotenv
import plotly.express as px

load_dotenv()

# ---------- DB CONNECTION ----------
@st.cache_resource
def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT"),
        sslmode="require"
    )

conn = get_connection()

# ---------- PAGE SETTINGS ----------
st.set_page_config(page_title="SECaaS Security Dashboard", layout="wide")
st.title("🔐 Insider Threat Detection Dashboard")

# ---------- LOAD DATA ----------
def load_alerts():
    query = """
        SELECT a.alert_id, u.username, r.role_name,
               a.risk_score, a.severity, a.reason, a.created_at
        FROM alerts a
        JOIN users u ON a.user_id = u.user_id
        JOIN roles r ON u.role_id = r.role_id
        ORDER BY a.created_at DESC
        LIMIT 100
    """
    return pd.read_sql(query, conn)

def load_logs():
    query = """
        SELECT l.log_id, u.username, l.action, l.resource,
               l.records_accessed, l.created_at
        FROM activity_logs l
        JOIN users u ON l.user_id = u.user_id
        ORDER BY l.created_at DESC
        LIMIT 100
    """
    return pd.read_sql(query, conn)

alerts_df = load_alerts()
logs_df = load_logs()

# ---------- ALERT SUMMARY ----------
st.subheader("🚨 Alerts Summary")

col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", len(alerts_df))
col2.metric("High Risk", len(alerts_df[alerts_df['severity']=="HIGH"]))
col3.metric("Medium Risk", len(alerts_df[alerts_df['severity']=="MEDIUM"]))

# ---------- ALERT TABLE ----------
st.subheader("🔴 Recent Alerts")

def color_severity(val):
    if val == "HIGH":
        return "background-color: #ff4b4b; color: white"
    elif val == "MEDIUM":
        return "background-color: #ffa500; color: black"
    else:
        return "background-color: #2ecc71; color: white"

styled_alerts = alerts_df.style.applymap(color_severity, subset=["severity"])
st.dataframe(styled_alerts, use_container_width=True)

# ---------- RISK DISTRIBUTION ----------
st.subheader("📊 Risk Distribution")

if not alerts_df.empty:
    fig = px.histogram(alerts_df, x="severity", color="severity",
                       color_discrete_map={
                           "HIGH":"red",
                           "MEDIUM":"orange",
                           "GREEN":"green"
                       })
    st.plotly_chart(fig, use_container_width=True)

# ---------- ACTIVITY LOGS ----------
st.subheader("📜 Recent Activity Logs")
st.dataframe(logs_df, use_container_width=True)

# ---------- AUTO REFRESH ----------
st.caption("Auto-refresh every 10 seconds")
st.experimental_rerun()
