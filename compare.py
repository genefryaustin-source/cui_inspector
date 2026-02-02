import json
import pandas as pd
import streamlit as st
from db import db, init_db
from auth import tenant_id, audit

def render_compare():
    st.header("🧾 Compare Runs (N vs N-1)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return
    init_db()
    with db() as con:
        rows = con.execute(
            "SELECT id, started_at, risk_level, patterns_json FROM inspections WHERE tenant_id=? ORDER BY started_at DESC LIMIT 500",
            (tid,),
        ).fetchall()

    df = pd.DataFrame([{"id": r["id"], "started_at": r["started_at"], "risk_level": r["risk_level"]} for r in rows])
    st.dataframe(df, use_container_width=True)
    if df.empty:
        return
    ids = df["id"].tolist()
    newer = st.selectbox("Newer inspection", ids, index=0)
    older = st.selectbox("Older inspection", ids, index=min(1, len(ids)-1))

    a = next((r for r in rows if int(r["id"]) == int(older)), None)
    b = next((r for r in rows if int(r["id"]) == int(newer)), None)
    if not a or not b:
        return

    audit("compare_runs", {"older": int(older), "newer": int(newer)})

    pa = json.loads(a["patterns_json"] or "{}")
    pb = json.loads(b["patterns_json"] or "{}")
    keys = sorted(set(pa) | set(pb))
    out = [{"pattern": k, "older": int(pa.get(k, 0)), "newer": int(pb.get(k, 0)), "delta": int(pb.get(k, 0)) - int(pa.get(k, 0))} for k in keys]
    st.subheader("Pattern deltas")
    st.dataframe(out, use_container_width=True)

    st.subheader("Risk delta")
    st.write({"older_risk": a["risk_level"], "newer_risk": b["risk_level"]})
