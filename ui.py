import streamlit as st

from db import init_db
from auth import render_login, require_login, logout
from tenants import ensure_active_tenant
from permissions import is_read_only
from audit_log import log_event

# Core pages
from document_inspector import render_document_inspector
from evidence_vault import render_evidence_vault
from search import render_search_page
from compare import render_compare_page
from manifest import render_manifest_export


# -------------------------------------------------
# Sidebar + Navigation
# -------------------------------------------------

def render_sidebar(user):
    st.sidebar.markdown(
        f"""
        **User:** {user['email']}  
        **Role:** `{user['role']}`
        """
    )

    if st.sidebar.button("Logout", key="logout_btn"):
        logout()

    st.sidebar.divider()

    page = st.sidebar.radio(
        "Navigation",
        [
            "Document Inspector",
            "Evidence Vault",
            "Search",
            "Compare",
            "Manifest Export",
        ],
        key="nav_radio",
    )

    return page


# -------------------------------------------------
# App Entrypoint
# -------------------------------------------------

def render_app():
    # --- DB bootstrap
    init_db()

    # --- Auth gate
    if not require_login():
        render_login()
        return

    user = st.session_state.user

    # --- Tenant enforcement
    ensure_active_tenant()

    # --- Sidebar
    page = render_sidebar(user)

    # --- RBAC guard: auditor is read-only
    if is_read_only(user["role"]) and page == "Document Inspector":
        st.warning("🔍 Auditor access is read-only. Uploads are disabled.")
        return

    # -------------------------------------------------
    # Page Routing
    # -------------------------------------------------

    if page == "Document Inspector":
        render_document_inspector()
        log_event(user, "document_inspection")

    elif page == "Evidence Vault":
        render_evidence_vault()

    elif page == "Search":
        render_search_page()

    elif page == "Compare":
        render_compare_page()

    elif page == "Manifest Export":
        render_manifest_export()
        log_event(user, "manifest_export")

    else:
        st.info("Select a page from the sidebar.")






