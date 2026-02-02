import streamlit as st
from auth import is_logged_in, render_login, render_logout_sidebar, is_superadmin, is_tenant_admin
from tenants import render_tenant_selector_sidebar, render_superadmin_tenant_management
from users import render_user_management
from inspector import render_inspector
from evidence import render_evidence_vault, render_verify_evidence_vault
from search import render_search
from compare import render_compare

def render_pages():
    if not is_logged_in():
        render_login()
        return

    render_logout_sidebar()
    render_tenant_selector_sidebar()

    pages = [
        "🧪 Inspect",
        "🗄️ Evidence Vault",
        "✅ Verify Evidence Vault",
        "🔎 Search",
        "🧾 Compare Runs",
        "📦 Evidence Manifest",
    ]
    if is_tenant_admin() or is_superadmin():
        pages.append("👥 Users")
    if is_superadmin():
        pages.append("🛡️ Tenants")

    page = st.sidebar.radio("Navigation", pages)

    if page == "🧪 Inspect":
        render_inspector()
    elif page == "🗄️ Evidence Vault":
        render_evidence_vault()
    elif page == "✅ Verify Evidence Vault":
        render_verify_evidence_vault()
    elif page == "🔎 Search":
        render_search()
    elif page == "🧾 Compare Runs":
        render_compare()
    elif page == "📦 Evidence Manifest":
        # Lazy import so this page cannot crash app startup
        try:
            from manifest import render_manifest_export
            render_manifest_export()
        except Exception as e:
            st.error(f"Manifest module error: {e}")
    elif page == "👥 Users":
        render_user_management()
    elif page == "🛡️ Tenants":
        render_superadmin_tenant_management()
