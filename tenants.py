import streamlit as st
from db import db, now_iso
from auth import is_superadmin, can_cross_tenant, tenant_id, set_tenant_id, audit

def ensure_default_tenant() -> int:
    with db() as con:
        # COALESCE handles legacy rows/columns
        try:
            r = con.execute("SELECT id FROM tenants WHERE COALESCE(is_active,1)=1 ORDER BY id ASC LIMIT 1").fetchone()
        except Exception:
            r = con.execute("SELECT id FROM tenants ORDER BY id ASC LIMIT 1").fetchone()

        if r:
            return int(r["id"])

        # Create default tenant
        try:
            con.execute("INSERT INTO tenants (name, created_at, is_active) VALUES (?, ?, 1)", ("default", now_iso()))
        except Exception:
            con.execute("INSERT INTO tenants (name, created_at) VALUES (?, ?)", ("default", now_iso()))
        return int(con.execute("SELECT id FROM tenants WHERE name='default'").fetchone()["id"])

def list_tenants(active_only: bool = True):
    with db() as con:
        if active_only:
            try:
                rows = con.execute("SELECT id, name FROM tenants WHERE COALESCE(is_active,1)=1 ORDER BY name").fetchall()
            except Exception:
                rows = con.execute("SELECT id, name FROM tenants ORDER BY name").fetchall()
        else:
            try:
                rows = con.execute("SELECT id, name, is_active, created_at FROM tenants ORDER BY name").fetchall()
            except Exception:
                rows = con.execute("SELECT id, name, created_at FROM tenants ORDER BY name").fetchall()
    return [dict(r) for r in rows]

def render_tenant_selector_sidebar():
    ensure_default_tenant()
    tenants = list_tenants(active_only=True)
    if not tenants:
        return

    if can_cross_tenant():
        opts = {t["name"]: int(t["id"]) for t in tenants}
        if tenant_id() is None:
            set_tenant_id(list(opts.values())[0])
        inv = {v: k for k, v in opts.items()}
        cur_name = inv.get(tenant_id(), list(opts.keys())[0])
        choice = st.sidebar.selectbox("Tenant", options=list(opts.keys()), index=list(opts.keys()).index(cur_name))
        set_tenant_id(opts[choice])
    else:
        tid = tenant_id()
        if tid is None:
            set_tenant_id(ensure_default_tenant())
            tid = tenant_id()
        tname = next((t["name"] for t in tenants if int(t["id"]) == int(tid)), "default")
        st.sidebar.markdown(f"**Tenant:** {tname}")

def render_superadmin_tenant_management():
    st.header("🛡️ SuperAdmin – Tenant Management")
    if not is_superadmin():
        st.error("SuperAdmin only.")
        return

    st.subheader("Create tenant")
    with st.form("create_tenant"):
        name = st.text_input("Tenant name (unique)").strip().lower()
        submitted = st.form_submit_button("Create tenant")
    if submitted:
        if not name:
            st.error("Tenant name required.")
        else:
            with db() as con:
                con.execute("INSERT INTO tenants (name, created_at, is_active) VALUES (?, ?, 1)", (name, now_iso()))
            audit("tenant_create", {"name": name})
            st.success("Tenant created.")
            st.rerun()

    st.divider()
    st.subheader("Tenants")
    st.dataframe(list_tenants(active_only=False), use_container_width=True)
