
import streamlit as st
import hashlib, os
from db import db

REPO = "data/repo"
os.makedirs(REPO, exist_ok=True)

def store_object(data: bytes) -> str:
    sha = hashlib.sha256(data).hexdigest()
    path = os.path.join(REPO, sha)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)
    return sha

def render_manifest():
    st.header("📦 Evidence Manifest")
    with db() as con:
        rows = con.execute(
            "SELECT username, event_type, created_at FROM audit_events ORDER BY created_at DESC"
        ).fetchall()
    csv = "username,event_type,created_at\n"
    for r in rows:
        csv += f"{r['username'] if 'username' in r.keys() else ''},{r['event_type']},{r['created_at']}\n"
    st.download_button("Download manifest.csv", csv.encode(), "manifest.csv")
