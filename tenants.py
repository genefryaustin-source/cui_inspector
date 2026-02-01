
import streamlit as st
from db import db, now_iso

def is_superadmin():
    u = st.session_state.get("auth_user")
    return u and u["role"] == "superadmin"

def render_tenant_admin():
    st.header("🏢 Tenant Management")
    if not is_superadmin():
        st.error("SuperAdmin only")
        return

    name = st.text_input("Tenant name").strip().lower()
    if st.button("Create tenant"):
        with db() as con:
            con.execute("INSERT INTO tenants (name,created_at) VALUES (?,?)", (name, now_iso()))
        st.success("Tenant created")
        st.rerun()

    with db() as con:
        rows = con.execute("SELECT * FROM tenants").fetchall()
    st.dataframe([dict(r) for r in rows])
