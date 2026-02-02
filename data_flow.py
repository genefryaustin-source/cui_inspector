import json
import streamlit as st
from db import db, init_db, now_iso
from auth import tenant_id, current_user, audit
from legacy_components import DataFlowMapper

def render_data_flow_mapper():
    st.header("🗺️ Data Flow Mapper (Persisted per Tenant)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return

    init_db()
    mapper = DataFlowMapper()

    with db() as con:
        saved = con.execute("SELECT id, name, created_at, created_by FROM data_flows WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100", (tid,)).fetchall()
    saved_list = [{"id": int(r["id"]), "name": r["name"], "created_at": r["created_at"], "created_by": r["created_by"]} for r in saved]

    col1, col2 = st.columns([2, 1])
    with col2:
        st.subheader("Saved flows")
        if saved_list:
            label_map = {f"{r['name']} (#{r['id']})": r["id"] for r in saved_list}
            pick = st.selectbox("Load", list(label_map.keys()))
            if st.button("Load selected"):
                fid = label_map[pick]
                with db() as con:
                    row = con.execute("SELECT flows_json FROM data_flows WHERE tenant_id=? AND id=?", (tid, fid)).fetchone()
                if row:
                    st.session_state["dfm_flows"] = json.loads(row["flows_json"])
                    audit("dataflow_loaded", {"flow_id": fid})
                    st.rerun()
        else:
            st.caption("No saved flows yet.")

        st.markdown("---")
        name = st.text_input("Save as", value="Data Flow Map").strip()
        if st.button("Save current flow map", type="primary"):
            flows = st.session_state.get("dfm_flows")
            if not flows:
                st.error("No flows in session yet. Add flows first.")
            else:
                with db() as con:
                    con.execute(
                        "INSERT INTO data_flows (tenant_id,name,flows_json,created_at,created_by) VALUES (?,?,?,?,?)",
                        (tid, name, json.dumps(flows), now_iso(), (current_user() or {}).get("username")),
                    )
                    con.commit()
                audit("dataflow_saved", {"name": name, "count": len(flows)})
                st.success("Saved.")
                st.rerun()

    with col1:
        st.caption("Legacy-style flow builder + DB persistence.")
        if "dfm_flows" not in st.session_state:
            st.session_state["dfm_flows"] = []

        with st.form("add_flow"):
            c1, c2 = st.columns(2)
            with c1:
                src = st.text_input("Source system", "")
                dst = st.text_input("Destination system", "")
                data_type = st.text_input("Data type", "CUI / FCI / PII")
            with c2:
                cui_present = st.selectbox("CUI present?", ["Yes", "No"])
                encryption = st.text_input("Encryption", "TLS 1.2+ / AES-256")
                cmmc_level = st.selectbox("CMMC level", ["L1", "L2", "L3"])
            submitted = st.form_submit_button("Add flow")

        if submitted:
            st.session_state["dfm_flows"].append({
                "source": src, "destination": dst, "data_type": data_type,
                "cui_present": (cui_present == "Yes"),
                "encryption": encryption, "cmmc_level": cmmc_level
            })
            audit("dataflow_added", {"source": src, "destination": dst})
            st.rerun()

        if st.session_state["dfm_flows"]:
            st.subheader("Current flows (session)")
            st.dataframe(st.session_state["dfm_flows"], use_container_width=True)
            if st.button("Clear session flows"):
                st.session_state["dfm_flows"] = []
                audit("dataflow_cleared", {})
                st.rerun()

            try:
                mermaid = mapper.generate_mermaid_diagram(st.session_state["dfm_flows"])
                st.code(mermaid, language="text")
            except Exception:
                pass
