import streamlit as st
from db import db, now_iso
from auth import is_superadmin, is_tenant_admin, tenant_id, pbkdf2_hash, audit

ROLE_CHOICES_SUPER = ["viewer", "analyst", "tenant_admin", "auditor"]
ROLE_CHOICES_TADMIN = ["viewer", "analyst"]

def render_user_management():
    st.header("👥 User Management")

    if not (is_superadmin() or is_tenant_admin()):
        st.error("Tenant Admins or SuperAdmins only.")
        return

    st.caption("Tenant Admins manage users within the selected tenant. SuperAdmins may also create cross-tenant auditors.")

    st.subheader("Create user")
    with st.form("create_user"):
        username = st.text_input("Username").strip().lower()
        password = st.text_input("Password", type="password")
        if is_superadmin():
            role = st.selectbox("Role", ROLE_CHOICES_SUPER)
            scope = st.selectbox("Scope", ["Selected tenant", "Cross-tenant (auditor only)"])
        else:
            role = st.selectbox("Role", ROLE_CHOICES_TADMIN)
            scope = "Selected tenant"
        submitted = st.form_submit_button("Create user")

    if submitted:
        if (not username) or (not password):
            st.error("Username and password required.")
            st.stop()

        tid = tenant_id()
        if tid is None:
            st.error("Select a tenant in the sidebar first.")
            st.stop()

        user_tenant_id = tid
        if is_superadmin() and role == "auditor" and scope.startswith("Cross-tenant"):
            user_tenant_id = None

        if (not is_superadmin()) and role in ("tenant_admin", "auditor", "superadmin"):
            st.error("Tenant Admins cannot create admin/auditor accounts.")
            st.stop()

        with db() as con:
            con.execute(
                "INSERT INTO users (tenant_id, username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (user_tenant_id, username, pbkdf2_hash(password), role, now_iso()),
            )
        audit("user_create", {"username": username, "role": role, "tenant_id": user_tenant_id})
        st.success("User created.")
        st.rerun()

    st.divider()
    st.subheader("Users")

    tid = tenant_id()
    with db() as con:
        if is_superadmin():
            rows = con.execute(
                "SELECT u.id, u.username, u.role, u.is_active, t.name AS tenant, u.created_at, u.last_login_at "
                "FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id "
                "ORDER BY u.created_at DESC LIMIT 500"
            ).fetchall()
        else:
            if tid is None:
                st.error("Select a tenant in the sidebar.")
                return
            rows = con.execute(
                "SELECT u.id, u.username, u.role, u.is_active, t.name AS tenant, u.created_at, u.last_login_at "
                "FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id "
                "WHERE u.tenant_id=? ORDER BY u.created_at DESC LIMIT 500",
                (tid,),
            ).fetchall()

    data = [dict(r) for r in rows]
    st.dataframe(data, use_container_width=True)

    if not data:
        return

    st.subheader("Disable / Reset password")
    user_ids = [r["id"] for r in data]
    selected = st.selectbox("User ID", options=user_ids)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Disable user"):
            with db() as con:
                con.execute("UPDATE users SET is_active=0 WHERE id=?", (int(selected),))
            audit("user_disable", {"user_id": int(selected)})
            st.success("User disabled.")
            st.rerun()

    with col2:
        with st.form("reset_password"):
            new_pw = st.text_input("New password", type="password")
            ok = st.form_submit_button("Reset password")
        if ok:
            if not new_pw:
                st.error("Password required.")
            else:
                with db() as con:
                    con.execute("UPDATE users SET password_hash=? WHERE id=?", (pbkdf2_hash(new_pw), int(selected)))
                audit("password_reset", {"user_id": int(selected)})
                st.success("Password reset.")
                st.rerun()
