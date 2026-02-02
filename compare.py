import json
import pandas as pd
import streamlit as st
from db import db
from auth import tenant_id, audit

def _load_inspection(con, ins_id: int):
    r = con.execute(
        "SELECT id, risk_level, patterns_json, categories_json, summary_json, started_at FROM inspections WHERE id=?",
        (ins_id,),
    ).fetchone()
    if not r:
        return None
    return {
        "id": int(r["id"]),
        "risk_level": r["risk_level"],
        "patterns": json.loads(r["patterns_json"] or "{}"),
        "categories": json.loads(r["categories_json"] or "[]"),
        "summary": json.loads(r["summary_json"] or "{}"),
        "started_at": r["started_at"],
    }

def _delta_dict(a: dict, b: dict):
    keys = set(a.keys()) | set(b.keys())
    out = []
    for k in sorted(keys):
        av = int(a.get(k, 0))
        bv = int(b.get(k, 0))
        out.append({"key": k, "a": av, "b": bv, "delta": bv - av})
    return out

def render_compare():
    st.header("🧾 Compare Runs (N vs N-1)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return

    with db() as con:
        rows = con.execute(
            "SELECT i.id, i.started_at, i.risk_level, av.original_filename, av.version_int, av.sha256 AS artifact_sha "
            "FROM inspections i LEFT JOIN artifact_versions av ON av.id=i.artifact_version_id "
            "WHERE i.tenant_id=? ORDER BY i.started_at DESC LIMIT 500",
            (tid,),
        ).fetchall()

    df = pd.DataFrame([dict(r) for r in rows])
    if df.empty:
        st.info("No inspections yet.")
        return

    st.dataframe(df[["id","started_at","original_filename","version_int","artifact_sha","risk_level"]], use_container_width=True)

    ids = df["id"].tolist()
    ins_b = st.selectbox("Newer inspection", options=ids, index=0)
    ins_a = st.selectbox("Older inspection", options=ids, index=min(1, len(ids)-1))

    with db() as con:
        a = _load_inspection(con, int(ins_a))
        b = _load_inspection(con, int(ins_b))

    if not a or not b:
        st.error("Could not load inspections.")
        return

    audit("compare_runs", {"a": a["id"], "b": b["id"]})

    st.subheader("Risk delta")
    st.write({"risk_a": a["risk_level"], "risk_b": b["risk_level"], "changed": a["risk_level"] != b["risk_level"]})

    st.subheader("Pattern deltas")
    st.dataframe(_delta_dict(a["patterns"], b["patterns"]), use_container_width=True)

    st.subheader("Category deltas")
    ad = {c.get("category"): int(c.get("hits", 0)) for c in (a["categories"] or []) if isinstance(c, dict)}
    bd = {c.get("category"): int(c.get("hits", 0)) for c in (b["categories"] or []) if isinstance(c, dict)}
    st.dataframe(_delta_dict(ad, bd), use_container_width=True)
