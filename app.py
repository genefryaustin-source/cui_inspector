
import sys
from pathlib import Path
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
from ui_pages import render_pages

st.set_page_config(page_title="CUI Inspector – Hotfix v3", layout="wide")

def main():
    render_pages()

if __name__ == "__main__":
    main()
