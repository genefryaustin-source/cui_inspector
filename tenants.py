
import streamlit as st
from db import db, now_iso
from auth import can_cross_tenant, tenant_id, set_tenant_id

def ensure_default_tenant() -> int:
    with db() as con:
        try:
            r = con.execute(
                "SELECT id FROM tenants WHERE COALESCE(is_active,1)=1 ORDER BY id ASC LIMIT 1"
            ).fetchone()
        except Exception:
            r = con.execute("SELECT id FROM tenants ORDER BY id ASC LIMIT 1").fetchone()

        if r:
            return int(r["id"])

        con.execute(
            "INSERT INTO tenants (name, created_at, is_active) VALUES (?, ?, 1)",
            ("default", now_iso()),
        )
        return int(con.execute("SELECT id FROM tenants WHERE name='default'").fetchone()["id"])

def render_tenant_selector_sidebar():
    tid = ensure_default_tenant()
    tenants = []
    with db() as con:
        rows = con.execute("SELECT id, name FROM tenants").fetchall()
        tenants = [dict(r) for r in rows]

    if not tenants:
        return

    if can_cross_tenant():
        opts = {t["name"]: int(t["id"]) for t in tenants}
        if tenant_id() is None:
            set_tenant_id(tid)
        inv = {v: k for k, v in opts.items()}
        cur = inv.get(tenant_id(), list(opts.keys())[0])
        choice = st.sidebar.selectbox("Tenant", list(opts.keys()), index=list(opts.keys()).index(cur))
        set_tenant_id(opts[choice])
    else:
        if tenant_id() is None:
            set_tenant_id(tid)
        name = next((t["name"] for t in tenants if int(t["id"]) == int(tenant_id())), "default")
        st.sidebar.markdown(f"**Tenant:** {name}")
