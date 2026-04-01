import streamlit as st
import pandas as pd
import sqlite3
import os
import time

st.set_page_config(page_title="Secure Log Monitor", page_icon="🛡️", layout="wide")

DB_PATH = "secure_logs.db"

def get_connection():
    if not os.path.exists(DB_PATH):
        st.error("Database not found. Make sure the server is running and logs are being collected.")
        st.stop()
    return sqlite3.connect(DB_PATH)

def fetch_data():
    conn = get_connection()
    logs_df = pd.read_sql("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100", conn)
    alerts_df = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20", conn)
    alerts_all = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp ASC", conn)
    devices_df = pd.read_sql("SELECT * FROM devices", conn)
    crypto_events_df = pd.read_sql("SELECT * FROM crypto_events ORDER BY timestamp DESC LIMIT 50", conn)
    conn.close()
    return logs_df, alerts_df, alerts_all, devices_df, crypto_events_df

# Title and Layout
st.title("🛡️ Secure Intelligent Log Analysis & Transformer Anomaly Detection")

# Auto-refresh using empty container and rerun
refresh_rate = st.sidebar.slider("Auto-refresh interval (seconds)", 5, 60, 5)

placeholder = st.empty()

with placeholder.container():
    try:
        logs_df, alerts_df, alerts_all, devices_df, crypto_events_df = fetch_data()
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Devices Monitored", len(devices_df))
        col2.metric("Recent Logs Analyzed", len(logs_df))
        if not alerts_all.empty:
            critical_alerts = len(alerts_all[alerts_all['severity'] == 'CRITICAL'])
        else:
            critical_alerts = 0
        col3.metric("Critical Alerts", critical_alerts, delta_color="inverse")
        col4.metric("Active Anomalies detected", len(alerts_df))
        
        st.markdown("---")
        
        # Row 2: Charts
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("📡 Predicted Log Sources Distribution")
            if not logs_df.empty:
                source_counts = logs_df['predicted_source'].value_counts().reset_index()
                source_counts.columns = ['Source', 'Count']
                st.bar_chart(source_counts.set_index('Source'))
            else:
                st.info("No logs collected yet.")

        with col_chart2:
            st.subheader("📈 Transformer Anomaly Probabilities")
            if not alerts_all.empty:
                alerts_ts = alerts_all.set_index(pd.to_datetime(alerts_all['timestamp']))
                st.line_chart(alerts_ts['anomaly_score'])
            else:
                st.info("No anomalies recorded.")
                
        st.markdown("---")

        # Row 3: Alerts Table
        st.subheader("⚠️ Recent Transformer Anomaly Alerts")
        if not alerts_df.empty:
            def highlight_severity(s):
                if s['severity'] == 'CRITICAL':
                    return ['background-color: #ff4b4b'] * len(s)
                elif s['severity'] == 'HIGH':
                    return ['background-color: #ff9d00'] * len(s)
                elif s['severity'] == 'MEDIUM':
                    return ['background-color: #ffe600'] * len(s)
                else:
                    return [''] * len(s)

            styled_alerts = alerts_df[['timestamp', 'severity', 'reason', 'anomaly_score', 'recommended_action']].style.apply(highlight_severity, axis=1)
            st.dataframe(styled_alerts, use_container_width=True)
        else:
            st.success("No recent alerts! System is operating normally.")
            
        st.markdown("---")
        
        # Row 4: Raw Logs
        st.subheader("📜 Live Event Logs (Encrypted & Processed)")
        if not logs_df.empty:
            display_logs = logs_df[['timestamp', 'device_id', 'predicted_source', 'source_confidence', 'raw_content']]
            st.dataframe(display_logs, use_container_width=True)

        st.markdown("---")

        # Row 5: Crypto Events
        st.subheader("🔑 Cryptographic Events")
        if not crypto_events_df.empty:
            st.dataframe(crypto_events_df, use_container_width=True)
        else:
            st.info("No cryptographic events recorded yet.")
            
    except Exception as e:
        st.error(f"Error loading dashboard: {e}")

time.sleep(refresh_rate)
st.rerun()