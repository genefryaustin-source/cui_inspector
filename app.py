import sys
from pathlib import Path

# -------------------------------------------------
# Ensure project root is on PYTHONPATH (CRITICAL)
# -------------------------------------------------
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
from ui import render_app

st.set_page_config(
    page_title="CUI Inspector – Multi-Tenant",
    layout="wide",
)

if __name__ == "__main__":
    render_app()

