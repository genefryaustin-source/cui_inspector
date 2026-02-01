import streamlit as st
from auth import is_logged_in, render_login

def render_pages():
    if not is_logged_in():
        render_login()
        return
    st.success("Login successful – core app loading next.")
