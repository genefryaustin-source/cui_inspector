import sys
import platform
import streamlit as st

from extractors import extract_text_from_file, OCR_AVAILABLE
from utils import now_iso, sha256_bytes
from rulesets import RULESETS, ruleset_names
from analysis_engine import analyze_text
from artifacts import build_artifacts, artifacts_to_download_buttons
from db import init_db
from evidence_vault import save_inspection, render_evidence_vault


def ensure_session_state():
    for k in ["last_text", "last_meta", "last_analysis", "artifacts"]:
        if k not in st.session_state:
            st.session_state[k] = None


def render_sidebar():
    st.sidebar.header("Navigation")
    page = st.sidebar.radio(
        "Go to",
        ["Document Inspector", "Evidence Vault", "System Info"]
    )

    st.sidebar.divider()
    st.sidebar.markdown("### Runtime")
    st.sidebar.caption(f"OCR available: **{OCR_AVAILABLE}**")

    st.sidebar.divider()
    st.sidebar.markdown("### System")
    st.sidebar.write(f"Python: {sys.version.split()[0]}")
    st.sidebar.write(f"Platform: {platform.system()}")

    return page


def render_document_inspector():
    colA, colB = st.columns([1.2, 0.8], gap="large")

    with colA:
        uploaded = st.file_uploader(
            "Upload a document",
            type=["pdf", "txt", "docx", "pptx"]
        )

        if uploaded:
            text = extract_text_from_file(uploaded)

            meta = {
                "filename": uploaded.name,
                "size_bytes": uploaded.size,
                "sha256": sha256_bytes(uploaded.getvalue()),
                "uploaded_at": now_iso(),
            }

            st.session_state.last_text = text
            st.session_state.last_meta = meta
            st.session_state.last_analysis = None
            st.session_state.artifacts = None

            st.subheader("File Metadata")
            st.json(meta)

            st.subheader("Extracted Text (preview)")
            st.text_area("Preview", text[:8000], height=260)
        else:
            st.info("Upload a document to begin.")

    with colB:
        st.subheader("Analysis Controls")

        rs_name = st.selectbox("Ruleset", ruleset_names())
        st.caption(RULESETS[rs_name]["description"])

        can_run = bool((st.session_state.last_text or "").strip())
        if st.button("▶ Run Analysis", type="primary", disabled=not can_run):
            analysis = analyze_text(st.session_state.last_text, rs_name)
            st.session_state.last_analysis = analysis
            st.session_state.artifacts = build_artifacts(
                st.session_state.last_meta,
                analysis
            )

            save_inspection(
                st.session_state.last_meta,
                analysis,
                st.session_state.artifacts
            )

        if st.session_state.last_analysis:
            a = st.session_state.last_analysis
            st.divider()
            st.metric("Risk Level", a["risk_level"])
            st.metric("Risk Score", a["risk_score"])
            st.metric("CUI Detected", "YES" if a["cui_detected"] else "NO")

            with st.expander("Details"):
                st.json(a)

            st.divider()
            st.subheader("Artifacts")
            artifacts_to_download_buttons(st.session_state.artifacts)


def render_system_info():
    st.header("System Info")
    st.write("Python:", sys.version)
    st.write("OCR available:", OCR_AVAILABLE)


def render_app():
    init_db()
    ensure_session_state()
    page = render_sidebar()

    if page == "Document Inspector":
        render_document_inspector()
    elif page == "Evidence Vault":
        render_evidence_vault()
    else:
        render_system_info()

