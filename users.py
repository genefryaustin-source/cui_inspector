import streamlit as st
import hashlib
from db import db, init_db, now_iso
from auth import is_superadmin, is_tenant_admin, tenant_id, audit, ROLES

def render_user_management():
    st.header("👥 User Management")
    init_db()
    if not (is_superadmin() or is_tenant_admin()):
        st.error("Admin only.")
        return

    tid = tenant_id()
    if tid is None and not is_superadmin():
        st.error("Select a tenant first.")
        return

    with db() as con:
        if is_superadmin():
            users = con.execute("SELECT id,tenant_id,username,role,is_active,created_at,last_login_at FROM users ORDER BY id").fetchall()
        else:
            users = con.execute("SELECT id,tenant_id,username,role,is_active,created_at,last_login_at FROM users WHERE tenant_id=? ORDER BY id", (tid,)).fetchall()
    st.dataframe([dict(u) for u in users], use_container_width=True)

    st.subheader("Create user")
    username = st.text_input("New username").strip()
    password = st.text_input("Temporary password", type="password")
    role_choices = ["tenant_admin","analyst","viewer"] if not is_superadmin() else ROLES
    role = st.selectbox("Role", role_choices)

    assign_tid = tid
    if is_superadmin():
        assign_tid_raw = st.number_input("Tenant ID (0 for none)", min_value=0, value=int(tid or 0), step=1)
        assign_tid = None if int(assign_tid_raw) == 0 else int(assign_tid_raw)

    if st.button("Create user", type="primary"):
        if not username or not password:
            st.error("Username and password required.")
            return
        ph = hashlib.sha256(password.encode("utf-8")).hexdigest()
        with db() as con:
            con.execute(
                "INSERT OR IGNORE INTO users (tenant_id,username,password_hash,role,is_active,created_at,last_login_at) VALUES (?,?,?,?,?,?,?)",
                (assign_tid, username, ph, role, 1, now_iso(), None),
            )
            con.commit()
        audit("user_created", {"username": username, "role": role, "tenant_id": assign_tid})
        st.success("User created.")
        st.rerun()
