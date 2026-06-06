# app.py

import streamlit as st
import pandas as pd

from evtx_parser import parse_evtx
from detector import detect_events
from risk_engine import calculate_risk
from report_exporter import export_csv

st.set_page_config(
    page_title="WinLog Sentinel",
    layout="wide"
)

st.title("🛡️ WinLog Sentinel")

uploaded = st.file_uploader(
    "Upload EVTX File",
    type=["evtx"]
)

if uploaded:

    temp_path = "temp.evtx"

    with open(temp_path, "wb") as f:
        f.write(uploaded.read())

    events = parse_evtx(temp_path)
    
    sample_ids = [e["EventID"] for e in events[:10]]
    st.write("🔍 First 10 Event IDs parsed:", sample_ids)

    findings, failed = detect_events(events)

    risk = calculate_risk(findings)

    st.subheader("Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        len(events)
    )

    col2.metric(
        "Findings",
        len(findings)
    )

    col3.metric(
        "Failed Logons",
        failed
    )

    col4.metric(
        "Risk",
        risk
    )

    st.divider()

    st.subheader("Detected Threats")

    for finding in findings:

        severity = finding["Severity"]

        msg = (
            f"{finding['Detection']} | "
            f"EID {finding['EventID']} | "
            f"{finding['Technique']} | "
            f"{finding['MITRE']}"
        )

        if severity == "CRITICAL":
            st.error("🚨 " + msg)

        elif severity == "HIGH":
            st.warning("⚠️ " + msg)

        elif severity == "MEDIUM":
            st.info("ℹ️ " + msg)

        else:
            st.success("✅ " + msg)

    st.divider()

    st.subheader("Detailed Findings")

    st.dataframe(
        pd.DataFrame(findings),
        use_container_width=True
    )

    if st.button("Export Report"):

        file = export_csv(findings)

        st.success(
            f"Report Saved: {file}"
        )