import streamlit as st
from db import init_db
from ui_pages import render_pages

st.set_page_config(page_title="CUI Inspector (Multi-Tenant)", page_icon="🔒", layout="wide")

def main():
    init_db()
    st.title("🔒 CUI Inspector – Complete Multi-Tenant")
    st.caption("Multi-tenant + restored document analysis + evidence vault + integrity verification + export manifests.")
    render_pages()

if __name__ == "__main__":
    main()
