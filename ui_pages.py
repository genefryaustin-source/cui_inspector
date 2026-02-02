
import streamlit as st
from auth import is_logged_in, render_login
from tenants import render_tenant_selector_sidebar

def render_pages():
    if not is_logged_in():
        render_login()
        return
    render_tenant_selector_sidebar()
    st.success("App loaded successfully with tenant selector.")
