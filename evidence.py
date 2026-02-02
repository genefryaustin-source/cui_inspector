import pandas as pd
import streamlit as st
from db import db, init_db
from auth import tenant_id, audit
from repo import read_object, verify_object

def render_evidence_vault():
    st.header("🗄️ Evidence Vault")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return
    init_db()
    with db() as con:
        rows = con.execute(
            "SELECT i.id, i.started_at, i.risk_level, av.original_filename "
            "FROM inspections i LEFT JOIN artifact_versions av ON av.id=i.artifact_version_id "
            "WHERE i.tenant_id=? ORDER BY i.started_at DESC LIMIT 300",
            (tid,),
        ).fetchall()
    df = pd.DataFrame([dict(r) for r in rows])
    st.dataframe(df, use_container_width=True)
    if df.empty:
        return
    ins_id = st.selectbox("Inspection", options=df["id"].tolist())
    with db() as con:
        files = con.execute(
            "SELECT id, kind, filename, sha256, size_bytes, object_relpath, created_at "
            "FROM evidence_files WHERE tenant_id=? AND inspection_id=? ORDER BY created_at DESC",
            (tid, int(ins_id)),
        ).fetchall()
    df2 = pd.DataFrame([dict(r) for r in files])
    st.dataframe(df2, use_container_width=True)
    if df2.empty:
        return
    ev_id = st.selectbox("Evidence file", options=df2["id"].tolist())
    rec = next((r for r in files if int(r["id"]) == int(ev_id)), None)
    if rec:
        st.download_button("⬇️ Download", data=read_object(rec["object_relpath"]), file_name=rec["filename"], mime="application/octet-stream")

def render_verify_evidence_vault():
    st.header("✅ Verify Evidence Integrity (SHA-256)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return
    init_db()
    if st.button("Run verification", type="primary"):
        problems = []
        checked = 0
        with db() as con:
            av = con.execute("SELECT id, sha256, object_relpath, original_filename FROM artifact_versions WHERE tenant_id=?", (tid,)).fetchall()
            ef = con.execute("SELECT id, sha256, object_relpath, filename FROM evidence_files WHERE tenant_id=?", (tid,)).fetchall()
        for r in av:
            ok, actual = verify_object(r["object_relpath"], r["sha256"]); checked += 1
            if not ok:
                problems.append({"table":"artifact_versions","id":int(r["id"]),"name":r["original_filename"],"expected":r["sha256"],"actual":actual})
        for r in ef:
            ok, actual = verify_object(r["object_relpath"], r["sha256"]); checked += 1
            if not ok:
                problems.append({"table":"evidence_files","id":int(r["id"]),"name":r["filename"],"expected":r["sha256"],"actual":actual})
        audit("verify_vault", {"checked": checked, "problems": len(problems)})
        st.write(f"Checked {checked} objects.")
        if problems:
            st.error("FAILED")
            st.dataframe(problems, use_container_width=True)
        else:
            st.success("PASSED")
