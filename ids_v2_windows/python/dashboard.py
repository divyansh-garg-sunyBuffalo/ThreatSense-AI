"""
dashboard.py — Streamlit dashboard reading from CSV written by C++ collector.
Run:  streamlit run dashboard.py
"""
import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="AI Cybersecurity Dashboard", layout="wide")
st.title("Shield: AI Cybersecurity Dashboard")

TRAFFIC_LOG = "data/traffic_logs.csv"

while True:
    try:
        df = pd.read_csv(TRAFFIC_LOG)
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Packet Size Over Time")
            st.line_chart(df["packet_size"])

        with col2:
            st.subheader("Protocol Distribution")
            st.bar_chart(df["protocol"].value_counts())

        st.subheader("Recent Packets")
        st.dataframe(df.tail(50), use_container_width=True)

    except FileNotFoundError:
        st.warning(f"Traffic log not found at `{TRAFFIC_LOG}`. Start the C++ backend first.")
    except Exception as e:
        st.error(f"Error: {e}")

    time.sleep(5)
    st.rerun()
