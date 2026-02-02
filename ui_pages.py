import streamlit as st
from auth import require_login, render_logout_sidebar, is_superadmin, is_tenant_admin
from tenants import render_tenant_selector_sidebar, render_superadmin_tenant_management
from users import render_user_management
from inspector import render_cui_inspector
from data_flow import render_data_flow_mapper
from evidence import render_evidence_vault, render_verify_evidence_vault
from search import render_search
from compare import render_compare
from manifest import render_manifest_export

def render_pages():
    if not require_login():
        return

    render_logout_sidebar()
    render_tenant_selector_sidebar()

    pages = [
        "📄 CUI Document Inspector",
        "🗺️ Data Flow Mapper",
        "🗄️ Evidence Vault",
        "✅ Verify Evidence Vault",
        "🔎 Search",
        "🧾 Compare Runs",
        "📦 Export Manifest",
    ]
    if is_tenant_admin() or is_superadmin():
        pages.append("👥 Users")
    if is_superadmin():
        pages.append("🛡️ Tenants")

    page = st.sidebar.radio("Navigation", pages)

    if page == "📄 CUI Document Inspector":
        render_cui_inspector()
    elif page == "🗺️ Data Flow Mapper":
        render_data_flow_mapper()
    elif page == "🗄️ Evidence Vault":
        render_evidence_vault()
    elif page == "✅ Verify Evidence Vault":
        render_verify_evidence_vault()
    elif page == "🔎 Search":
        render_search()
    elif page == "🧾 Compare Runs":
        render_compare()
    elif page == "📦 Export Manifest":
        render_manifest_export()
    elif page == "👥 Users":
        render_user_management()
    elif page == "🛡️ Tenants":
        render_superadmin_tenant_management()
