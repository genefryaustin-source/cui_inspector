import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
from ui import render_app

st.set_page_config(page_title="CUI Document Inspector", layout="wide")
st.title("📄 CUI Document Inspector")

render_app()
