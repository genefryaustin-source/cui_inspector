
import streamlit as st
from db import db

def render_manifest():
    st.header("📦 Evidence Manifest")
    with db() as con:
        rows = con.execute(
            "SELECT event_type, created_at FROM audit_events ORDER BY created_at DESC"
        ).fetchall()
    csv = "event_type,created_at\n"
    for r in rows:
        csv += f"{r['event_type']},{r['created_at']}\n"
    st.download_button("Download manifest.csv", csv.encode(), "manifest.csv")
