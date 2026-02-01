import json
import secrets
import hashlib
import streamlit as st
from db import db, now_iso

def pbkdf2_hash(password: str, iters: int = 200_000) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
    return f"pbkdf2_sha256${iters}${salt}${dk.hex()}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt, hexhash = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iters_s))
        return dk.hex() == hexhash
    except Exception:
        return False

def current_user():
    return st.session_state.get("auth_user")

def is_logged_in() -> bool:
    return current_user() is not None

def role() -> str:
    u = current_user()
    return u["role"] if u else ""

def is_superadmin() -> bool:
    return role() == "superadmin"

def is_tenant_admin() -> bool:
    return role() == "tenant_admin"

def is_auditor() -> bool:
    return role() == "auditor"

def can_cross_tenant() -> bool:
    return is_superadmin() or is_auditor()

def require_role(*roles):
    if role() not in roles:
        st.error("Insufficient permissions.")
        st.stop()

def tenant_id():
    return st.session_state.get("tenant_id")

def set_tenant_id(tid):
    st.session_state["tenant_id"] = tid

def audit(event_type: str, details: dict | None = None):
    u = current_user()
    with db() as con:
        con.execute(
            "INSERT INTO audit_events (tenant_id, user_id, event_type, details_json, created_at) VALUES (?,?,?,?,?)",
            (tenant_id(), u["id"] if u else None, event_type, json.dumps(details or {}), now_iso()),
        )

def render_superadmin_recovery_banner():
    if st.secrets.get("SUPERADMIN_RECOVERY") != "ENABLED":
        return

    st.warning("⚠️ SuperAdmin Recovery Mode Enabled (disable after use)")
    pw = st.text_input("Recovery password", type="password", key="recovery_pw")
    if st.button("Recover SuperAdmin", key="recover_btn"):
        if pw != st.secrets.get("SUPERADMIN_RECOVERY_PASSWORD"):
            st.error("Invalid recovery password")
            st.stop()
        with db() as con:
            r = con.execute("SELECT id FROM users WHERE role='superadmin' LIMIT 1").fetchone()
            if r:
                con.execute("UPDATE users SET password_hash=? WHERE role='superadmin'", (pbkdf2_hash(pw),))
            else:
                con.execute(
                    "INSERT INTO users (tenant_id, username, password_hash, role, is_active, created_at) VALUES (NULL, ?, ?, 'superadmin', 1, ?)",
                    ("superadmin", pbkdf2_hash(pw), now_iso()),
                )
        audit("superadmin_recovered", {})
        st.success("SuperAdmin recovered. Remove recovery secrets and reload.")
        st.stop()

def render_login():
    render_superadmin_recovery_banner()

    st.header("🔐 Sign in")
    with db() as con:
        user_count = int(con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])

    if user_count == 0:
        st.info("First run: create the initial SuperAdmin account.")
        username = st.text_input("SuperAdmin username", value="superadmin").strip().lower()
        password = st.text_input("SuperAdmin password", type="password")
        confirm = st.text_input("Confirm password", type="password")
        if st.button("Create SuperAdmin"):
            if not username or not password or password != confirm:
                st.error("Provide a username and matching passwords.")
                st.stop()
            with db() as con:
                con.execute(
                    "INSERT INTO users (tenant_id, username, password_hash, role, is_active, created_at) VALUES (NULL, ?, ?, 'superadmin', 1, ?)",
                    (username, pbkdf2_hash(password), now_iso()),
                )
            st.success("Created. Please sign in.")
        return

    username = st.text_input("Username").strip().lower()
    password = st.text_input("Password", type="password")

    if st.button("Sign in"):
        with db() as con:
            r = con.execute(
                "SELECT id, tenant_id, username, password_hash, role, is_active FROM users WHERE username=?",
                (username,),
            ).fetchone()
            if not r or int(r["is_active"]) != 1 or not pbkdf2_verify(password, r["password_hash"]):
                st.error("Invalid credentials")
                st.stop()
            con.execute("UPDATE users SET last_login_at=? WHERE id=?", (now_iso(), int(r["id"])))
        st.session_state["auth_user"] = {
            "id": int(r["id"]),
            "username": r["username"],
            "role": r["role"],
            "tenant_id": (int(r["tenant_id"]) if r["tenant_id"] is not None else None),
        }
        if can_cross_tenant():
            set_tenant_id(None)
        else:
            set_tenant_id(int(r["tenant_id"]) if r["tenant_id"] is not None else None)
        audit("login_success", {"username": r["username"], "role": r["role"]})
        st.success("Signed in")
        st.rerun()

def render_logout_sidebar():
    u = current_user()
    if not u:
        return
    st.sidebar.markdown(f"**Signed in:** {u['username']} ({u['role']})")
    if st.sidebar.button("Sign out"):
        audit("logout", {"username": u["username"]})
        st.session_state.pop("auth_user", None)
        st.session_state.pop("tenant_id", None)
        st.rerun()
