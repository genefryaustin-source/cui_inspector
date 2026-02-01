
import streamlit as st
import hashlib, secrets, json
from db import db, now_iso

def pbkdf2_hash(password: str, iters: int = 200_000) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iters)
    return f"pbkdf2_sha256${iters}${salt}${dk.hex()}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        _, iters, salt, hexhash = stored.split("$", 3)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters))
        return dk.hex() == hexhash
    except Exception:
        return False

def current_user():
    return st.session_state.get("auth_user")

def require_login():
    return current_user() is not None

def audit(event_type, details=None):
    u = current_user()
    with db() as con:
        con.execute(
            "INSERT INTO audit_events (tenant_id, user_id, event_type, details_json, created_at) VALUES (?,?,?,?,?)",
            (
                st.session_state.get("tenant_id"),
                u["id"] if u else None,
                event_type,
                json.dumps(details or {}),
                now_iso(),
            ),
        )

def render_superadmin_recovery():
    # Only show recovery UI if explicitly enabled
    if st.secrets.get("SUPERADMIN_RECOVERY") != "ENABLED":
        return False

    st.warning("⚠️ SuperAdmin Recovery Mode Enabled")

    recovery_pw = st.text_input("Recovery password", type="password")
    if st.button("Recover SuperAdmin"):
        if recovery_pw != st.secrets.get("SUPERADMIN_RECOVERY_PASSWORD"):
            st.error("Invalid recovery password")
            st.stop()

        with db() as con:
            r = con.execute("SELECT id FROM users WHERE role='superadmin' LIMIT 1").fetchone()
            if r:
                con.execute(
                    "UPDATE users SET password_hash=? WHERE role='superadmin'",
                    (pbkdf2_hash(recovery_pw),),
                )
            else:
                con.execute(
                    "INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                    ("superadmin", pbkdf2_hash(recovery_pw), "superadmin", now_iso()),
                )

        audit("superadmin_recovered", {})
        st.success("SuperAdmin recovered. Disable recovery secrets and reload.")
        st.stop()

    # IMPORTANT: allow normal login to render underneath
    return False

def render_login():
    # Show recovery banner if enabled, but do not block login
    render_superadmin_recovery()

    st.header("🔐 Sign in")

    with db() as con:
        cnt = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if cnt == 0:
        st.warning("Bootstrap SuperAdmin")
        username = st.text_input("Username", "superadmin").strip().lower()
        password = st.text_input("Password", type="password")
        if st.button("Create SuperAdmin"):
            with db() as con:
                con.execute(
                    "INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                    (username, pbkdf2_hash(password), "superadmin", now_iso()),
                )
            st.success("SuperAdmin created. Reload the app.")
            st.stop()
        return

    username = st.text_input("Username").strip().lower()
    password = st.text_input("Password", type="password")
    if st.button("Sign in"):
        with db() as con:
            r = con.execute(
                "SELECT id,username,password_hash,role,tenant_id FROM users WHERE username=? AND is_active=1",
                (username,),
            ).fetchone()
        if not r or not pbkdf2_verify(password, r[2]):
            st.error("Invalid credentials")
            st.stop()

        st.session_state["auth_user"] = {
            "id": r[0],
            "username": r[1],
            "role": r[3],
            "tenant_id": r[4],
        }
        st.session_state["tenant_id"] = r[4]
        audit("login_success", {"username": r[1], "role": r[3]})
        st.success("Signed in")
        st.rerun()

def render_logout():
    if current_user():
        st.sidebar.markdown(f"**User:** {current_user()['username']} ({current_user()['role']})")
        if st.sidebar.button("Logout"):
            audit("logout", {"username": current_user()["username"]})
            st.session_state.clear()
            st.rerun()
