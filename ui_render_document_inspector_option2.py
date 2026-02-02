# Replace render_document_inspector() in ui.py with this function.
# Keep the rest of ui.py intact (nav, Evidence Vault, Search, Compare, Manifest Export, etc.)

import streamlit as st
from extractors import extract_text_from_file
from utils import now_iso, sha256_bytes
from rulesets import RULESETS, ruleset_names
from analysis_engine import analyze_text
from artifacts import build_artifacts, artifacts_to_download_buttons
from evidence_vault import save_inspection


def render_document_inspector():
    colA, colB = st.columns([1.2, 0.8], gap="large")

    with colA:
        uploaded = st.file_uploader(
            "Upload a document",
            type=["pdf", "txt", "docx", "pptx"],
            key="doc_upload"
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
            st.text_area("Preview", text[:8000], height=260, key="preview_text")

    with colB:
        st.subheader("Analysis Controls")

        rs_name = st.selectbox("Ruleset", ruleset_names(), key="ruleset_select")
        st.caption(RULESETS[rs_name]["description"])

        can_run = bool((st.session_state.last_text or "").strip())
        if st.button("▶ Run Analysis", type="primary", disabled=not can_run, key="run_analysis"):
            analysis = analyze_text(st.session_state.last_text, rs_name)
            st.session_state.last_analysis = analysis
            st.session_state.artifacts = build_artifacts(st.session_state.last_meta, analysis)

            save_inspection(st.session_state.last_meta, analysis, st.session_state.artifacts)

        if st.session_state.last_analysis:
            a = st.session_state.last_analysis

            st.divider()
            st.markdown(f"### 📄 {st.session_state.last_meta.get('filename','(document)')}")

            m1, m2, m3 = st.columns(3)
            m1.metric("CUI Detected", "YES" if a.get("cui_detected") else "NO")
            m2.metric("Risk Level", a.get("risk_level", ""))
            m3.metric("Risk Score", a.get("risk_score", 0))

            with st.expander("🔍 Detection Signals", expanded=True):
                for i, s in enumerate(a.get("signals", []), 1):
                    st.write(f"{i}. {s}")

            pf = a.get("patterns_found", {}) or {}
            st.markdown(f"**Patterns Found:** {sum(int(v) for v in pf.values())}")

            with st.expander("🧬 Detected Patterns"):
                dps = a.get("detected_patterns", [])
                if not dps:
                    st.caption("No structured pattern hits.")
                else:
                    for dp in dps:
                        st.markdown(f"**{dp.get('pattern')}** — {dp.get('category','')} (conf: {dp.get('confidence')})")
                        st.caption(dp.get("excerpt",""))

            with st.expander("📋 CUI Categories Identified"):
                cats = a.get("cui_categories", [])
                if not cats:
                    st.caption("No category inference available for this document.")
                else:
                    for c in cats:
                        st.write(f"- {c.get('category')} (confidence: {c.get('confidence')})")

            with st.expander("💡 CMMC / NIST / FedRAMP Recommendations", expanded=True):
                recs = a.get("recommendations", [])
                for i, r in enumerate(recs, 1):
                    st.write(f"{i}. {r}")

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
            st.divider()
            st.subheader("Artifacts")
            artifacts_to_download_buttons(st.session_state.artifacts)
