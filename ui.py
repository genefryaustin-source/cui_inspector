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
from search import render_search_page
from compare import render_compare_page
from manifest import render_manifest_export


# -------------------------
# Session state bootstrap
# -------------------------

def ensure_session_state():
    defaults = {
        "last_text": None,
        "last_meta": None,
        "last_analysis": None,
        "artifacts": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# -------------------------
# Sidebar / Navigation
# -------------------------

def render_sidebar():
    st.sidebar.header("Navigation")

    page = st.sidebar.radio(
        "Go to",
        [
            "Document Inspector",
            "Evidence Vault",
            "Search",
            "Compare",
            "Manifest Export",
            "System Info",
        ],
        key="nav_radio",
    )

    st.sidebar.divider()
    st.sidebar.markdown("### Runtime")
    st.sidebar.caption(f"OCR available: **{OCR_AVAILABLE}**")

    st.sidebar.divider()
    st.sidebar.markdown("### System")
    st.sidebar.write(f"Python: {sys.version.split()[0]}")
    st.sidebar.write(f"Platform: {platform.system()}")

    return page


# -------------------------
# Document Inspector (Option 2)
# -------------------------

def render_document_inspector():
    col_left, col_right = st.columns([1.2, 0.8], gap="large")

    # ---- Upload / Extract
    with col_left:
        uploaded = st.file_uploader(
            "Upload a document",
            type=["pdf", "txt", "docx", "pptx"],
            key="doc_upload",
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
            st.text_area(
                "Preview",
                text[:8000],
                height=260,
                key="preview_text",
            )

    # ---- Analysis Controls / Results
    with col_right:
        st.subheader("Analysis Controls")

        ruleset = st.selectbox(
            "Ruleset",
            ruleset_names(),
            key="ruleset_select",
        )
        st.caption(RULESETS[ruleset]["description"])

        can_run = bool((st.session_state.last_text or "").strip())
        if st.button(
            "▶ Run Analysis",
            type="primary",
            disabled=not can_run,
            key="run_analysis",
        ):
            analysis = analyze_text(st.session_state.last_text, ruleset)
            st.session_state.last_analysis = analysis
            st.session_state.artifacts = build_artifacts(
                st.session_state.last_meta,
                analysis,
            )

            save_inspection(
                st.session_state.last_meta,
                analysis,
                st.session_state.artifacts,
            )

        # ---- Results (Option 2 rich output)
        if st.session_state.last_analysis:
            a = st.session_state.last_analysis
            meta = st.session_state.last_meta or {}

            st.divider()
            st.markdown(f"### 📄 {meta.get('filename', '(document)')}")

            m1, m2, m3 = st.columns(3)
            m1.metric("CUI Detected", "YES" if a.get("cui_detected") else "NO")
            m2.metric("Risk Level", a.get("risk_level", ""))
            m3.metric("Risk Score", a.get("risk_score", 0))

            # ---- Detection signals
            with st.expander("🔍 Detection Signals", expanded=True):
                for i, sig in enumerate(a.get("signals", []), start=1):
                    st.write(f"{i}. {sig}")

            # ---- Pattern summary
            patterns_found = a.get("patterns_found", {}) or {}
            total_patterns = sum(int(v) for v in patterns_found.values())
            st.markdown(f"**Patterns Found:** {total_patterns}")

            with st.expander("🧬 Detected Patterns"):
                dps = a.get("detected_patterns", [])
                if not dps:
                    st.caption("No structured pattern hits.")
                else:
                    for dp in dps:
                        st.markdown(
                            f"**{dp.get('pattern')}** — {dp.get('category','')} "
                            f"(confidence: {dp.get('confidence')})"
                        )
                        st.caption(dp.get("excerpt", ""))

            # ---- CUI categories
            with st.expander("📋 CUI Categories Identified"):
                cats = a.get("cui_categories", [])
                if not cats:
                    st.caption("No category inference available for this document.")
                else:
                    for c in cats:
                        st.write(
                            f"- {c.get('category')} "
                            f"(confidence: {c.get('confidence')})"
                        )

            # ---- Recommendations + compliance mapping
            with st.expander(
                "💡 CMMC / NIST / FedRAMP Recommendations",
                expanded=True,
            ):
                for i, rec in enumerate(a.get("recommendations", []), start=1):
                    st.write(f"{i}. {rec}")

                cm = a.get("compliance_mapping", {})
                if cm:
                    st.markdown("**Control Mapping (high-level)**")
                    c1, c2, c3 = st.columns(3)

                    with c1:
                        st.markdown("**CMMC Level 2**")
                        for row in cm.get("CMMC_Level_2", []):
                            st.write(f"- {row.get('control')}: {row.get('title')}")

                    with c2:
                        st.markdown("**NIST SP 800-171**")
                        for row in cm.get("NIST_SP_800_171", []):
                            st.write(f"- {row.get('control')}: {row.get('title')}")

                    with c3:
                        st.markdown("**FedRAMP Moderate**")
                        for row in cm.get("FedRAMP_Moderate", []):
                            st.write(f"- {row.get('control')}: {row.get('title')}")

            # ---- Artifacts
            st.divider()
            st.subheader("Artifacts")
            artifacts_to_download_buttons(st.session_state.artifacts)


# -------------------------
# System Info
# -------------------------

def render_system_info():
    st.header("System Info")
    st.write("Python:", sys.version)
    st.write("OCR available:", OCR_AVAILABLE)


# -------------------------
# App Entrypoint
# -------------------------

def render_app():
    init_db()
    ensure_session_state()
    page = render_sidebar()

    if page == "Document Inspector":
        render_document_inspector()
    elif page == "Evidence Vault":
        render_evidence_vault()
    elif page == "Search":
        render_search_page()
    elif page == "Compare":
        render_compare_page()
    elif page == "Manifest Export":
        render_manifest_export()
    else:
        render_system_info()




