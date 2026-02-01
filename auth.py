import json, secrets, hashlib
import streamlit as st
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

def is_logged_in():
    return current_user() is not None

def audit(event_type, details=None):
    u = current_user()
    with db() as con:
        con.execute(
            "INSERT INTO audit_events (tenant_id, user_id, event_type, details_json, created_at) VALUES (?,?,?,?,?)",
            (st.session_state.get("tenant_id"), u["id"] if u else None, event_type, json.dumps(details or {}), now_iso())
        )

def render_login():
    st.header("🔐 Sign in")
    username = st.text_input("Username").strip().lower()
    password = st.text_input("Password", type="password")
    if st.button("Sign in"):
        with db() as con:
            r = con.execute(
                "SELECT id, tenant_id, username, password_hash, role, is_active FROM users WHERE username=?",
                (username,)
            ).fetchone()
            if not r or int(r["is_active"]) != 1 or not pbkdf2_verify(password, r["password_hash"]):
                st.error("Invalid credentials")
                st.stop()
            con.execute("UPDATE users SET last_login_at=? WHERE id=?", (now_iso(), int(r["id"])))

        st.session_state["auth_user"] = {
            "id": int(r["id"]),
            "username": r["username"],
            "role": r["role"],
            "tenant_id": r["tenant_id"],
        }
        audit("login_success", {"username": r["username"], "role": r["role"]})
        st.success("Signed in")
        st.rerun()
