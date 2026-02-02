import streamlit as st
from db import db, init_db, now_iso
from auth import is_superadmin, is_auditor, tenant_id, audit

def ensure_default_tenant():
    init_db()
    with db() as con:
        r = con.execute("SELECT id FROM tenants WHERE is_active=1 ORDER BY id ASC LIMIT 1").fetchone()
        if r:
            return int(r["id"])
        con.execute("INSERT INTO tenants (name,is_active,created_at) VALUES (?,?,?)", ("Default",1,now_iso()))
        con.commit()
        return int(con.execute("SELECT id FROM tenants WHERE name='Default'").fetchone()["id"])

def render_tenant_selector_sidebar():
    init_db()
    if tenant_id() is None and not (is_superadmin() or is_auditor()):
        return

    with db() as con:
        tenants = con.execute("SELECT id,name FROM tenants WHERE is_active=1 ORDER BY name").fetchall()

    if not tenants:
        ensure_default_tenant()
        with db() as con:
            tenants = con.execute("SELECT id,name FROM tenants WHERE is_active=1 ORDER BY name").fetchall()

    opts = {f"{t['name']} (#{t['id']})": int(t["id"]) for t in tenants}
    labels = list(opts.keys())
    current = st.session_state.get("tenant_id")
    idx = 0
    if current:
        for i, lab in enumerate(labels):
            if opts[lab] == int(current):
                idx = i
                break

    st.sidebar.markdown("### Tenant")
    choice = st.sidebar.selectbox("Tenant", labels, index=idx)
    st.session_state["tenant_id"] = opts[choice]

def render_superadmin_tenant_management():
    st.header("🛡️ Tenant Management (SuperAdmin)")
    if not is_superadmin():
        st.error("SuperAdmin only.")
        return
    init_db()
    with db() as con:
        tenants = con.execute("SELECT id,name,is_active,created_at FROM tenants ORDER BY id").fetchall()
    st.dataframe([dict(t) for t in tenants], use_container_width=True)

    st.subheader("Create tenant")
    name = st.text_input("Tenant name").strip()
    if st.button("Create tenant", type="primary"):
        if not name:
            st.error("Name required.")
            return
        with db() as con:
            con.execute("INSERT OR IGNORE INTO tenants (name,is_active,created_at) VALUES (?,?,?)", (name,1,now_iso()))
            con.commit()
        audit("tenant_created", {"name": name})
        st.rerun()
