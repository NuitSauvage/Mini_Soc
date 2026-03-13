import streamlit as st
import pandas as pd

from utils import load_data, build_incidents
from llm_helper import generate_incident_summary

st.set_page_config(page_title="MiniSOC Copilot", layout="wide")

st.title("MiniSOC Copilot")
st.caption("GenAI-assisted incident triage prototype for SOC analysts")

st.warning(
    "AI-generated analysis is decision support only. Logs and email content are untrusted input. Human validation is required before any response action."
)

auth, email, endpoint = load_data()
incidents = build_incidents(auth, email, endpoint)

summary_rows = []
for inc in incidents:
    summary_rows.append({
        "incident_id": inc["incident_id"],
        "user": inc["user"],
        "severity": inc["severity"],
        "score": inc["score"],
        "signals": len(inc["reasons"]),
    })

df_incidents = pd.DataFrame(summary_rows).sort_values(by="score", ascending=False)

severity_filter = st.multiselect(
    "Filter by severity",
    options=["low", "medium", "high", "critical"],
    default=["medium", "high", "critical"]
)

filtered = df_incidents[df_incidents["severity"].isin(severity_filter)]

st.subheader("Incident Queue")
st.dataframe(filtered, use_container_width=True)

incident_ids = filtered["incident_id"].tolist()
selected_id = st.selectbox("Select an incident", incident_ids)

selected = next(i for i in incidents if i["incident_id"] == selected_id)

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Triggered Reasons")
    for r in selected["reasons"]:
        st.write(f"- {r}")

    st.subheader("Timeline")
    for event in selected["timeline"]:
        st.write(f"**{event['timestamp']}** | {event['source']} | {event['event']}")

with col2:
    st.subheader("AI Incident Summary")
    st.text_area(
        label="Summary",
        value=generate_incident_summary(selected),
        height=320
    )

    st.subheader("Raw Email Context")
    st.json(selected["raw_email"])