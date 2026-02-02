import sys
import platform
from pathlib import Path
from datetime import datetime
import hashlib
import json
import re
from typing import Dict, Any, List

import streamlit as st
import pandas as pd

# =============================================================================
# Bootstrap (Streamlit Cloud safe)
# =============================================================================
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# =============================================================================
# Optional OCR dependencies
# =============================================================================
OCR_AVAILABLE = True
try:
    import pytesseract  # type: ignore
except Exception:
    pytesseract = None
    OCR_AVAILABLE = False

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None

try:
    import pdf2image  # type: ignore
except Exception:
    pdf2image = None
    OCR_AVAILABLE = False

# =============================================================================
# Optional config
# =============================================================================
try:
    from config import TESSERACT_CMD, POPPLER_PATH, OCR_DPI, OCR_LANGUAGE
except Exception:
    TESSERACT_CMD = ""
    POPPLER_PATH = None
    OCR_DPI = 300
    OCR_LANGUAGE = "eng"

if pytesseract and TESSERACT_CMD:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD

# =============================================================================
# App config
# =============================================================================
st.set_page_config(page_title="CUI Document Inspector", layout="wide")
st.title("📄 CUI Document Inspector")

# =============================================================================
# Sidebar (indentation-proof)
# =============================================================================
st.sidebar.header("Navigation")
page = st.sidebar.radio("Go to", ["Document Inspector", "System Info"])

st.sidebar.divider()
st.sidebar.markdown("### ✅ Runtime Checks")
st.sidebar.caption(f"OCR available: **{OCR_AVAILABLE}**")

st.sidebar.divider()
st.sidebar.markdown("### ℹ️ System Information")
st.sidebar.write(f"Python: {sys.version.split()[0]}")
st.sidebar.write(f"Platform: {platform.system()} {platform.release()}")

# =============================================================================
# Utilities
# =============================================================================
def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))

# =============================================================================
# Extraction
# =============================================================================
def extract_text_from_pdf(uploaded_file) -> str:
    from PyPDF2 import PdfReader
    reader = PdfReader(uploaded_file)
    text_parts = []
    for pg in reader.pages:
        t = pg.extract_text() or ""
        if t:
            text_parts.append(t)
    text = "\n".join(text_parts)

    if not text.strip():
        if not OCR_AVAILABLE:
            st.warning("⚠️ PDF appears scanned but OCR is unavailable.")
            return ""
        try:
            images = pdf2image.convert_from_bytes(
                uploaded_file.getvalue(),
                dpi=OCR_DPI,
                poppler_path=POPPLER_PATH,
            )
            text = "\n".join(
                pytesseract.image_to_string(img, lang=OCR_LANGUAGE)
                for img in images
            )
        except Exception as e:
            st.error(f"OCR failed: {e}")
            return ""
    return text

def extract_text_from_file(uploaded_file) -> str:
    name = (uploaded_file.name or "").lower()
    if name.endswith(".pdf"):
        return extract_text_from_pdf(uploaded_file)
    if name.endswith(".txt"):
        return uploaded_file.getvalue().decode("utf-8", errors="ignore")
    if name.endswith(".docx"):
        from docx import Document
        doc = Document(uploaded_file)
        return "\n".join(p.text for p in doc.paragraphs)
    if name.endswith(".pptx"):
        from pptx import Presentation
        prs = Presentation(uploaded_file)
        out = []
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    if shape.text.strip():
                        out.append(shape.text.strip())
        return "\n".join(out)
    return ""

# =============================================================================
# RULESETS (Step 3 retained)
# =============================================================================
RULESETS = {
    "Basic": {
        "description": "Balanced detection. Email is sensitive, not CUI.",
        "cui_patterns": {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "DoD_ID": r"\b\d{10}\b",
        },
        "sensitive_patterns": {
            "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        },
        "keywords": ["controlled unclassified information", "cui", "fouo"],
        "weights": {"cui": 20, "sensitive": 5, "keyword": 8, "multi_bonus": 10},
    },
    "DoD / GovCon": {
        "description": "Stricter profile for defense contractors.",
        "cui_patterns": {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "DoD_ID": r"\b\d{10}\b",
            "CAGE": r"\b[A-HJ-NP-Z0-9]{5}\b",
        },
        "sensitive_patterns": {
            "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        },
        "keywords": ["itar", "ear", "dfars", "export controlled"],
        "weights": {"cui": 25, "sensitive": 5, "keyword": 10, "multi_bonus": 15},
    },
}

# =============================================================================
# Analysis
# =============================================================================
def analyze_text(text: str, ruleset_name: str) -> Dict[str, Any]:
    rs = RULESETS[ruleset_name]
    t = text or ""
    tlow = t.lower()

    cui_hits, sens_hits, kw_hits = {}, {}, []

    for k, pat in rs["cui_patterns"].items():
        hits = re.findall(pat, t, flags=re.IGNORECASE)
        if hits:
            cui_hits[k] = len(hits)

    for k, pat in rs["sensitive_patterns"].items():
        hits = re.findall(pat, t, flags=re.IGNORECASE)
        if hits:
            sens_hits[k] = len(hits)

    for kw in rs["keywords"]:
        if kw in tlow:
            kw_hits.append(kw)

    score = (
        sum(cui_hits.values()) * rs["weights"]["cui"]
        + sum(sens_hits.values()) * rs["weights"]["sensitive"]
        + len(kw_hits) * rs["weights"]["keyword"]
    )
    if len(cui_hits) >= 2:
        score += rs["weights"]["multi_bonus"]

    risk_score = int(clamp(score, 0, 100))
    risk = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 30 else "LOW"

    return {
        "ruleset": ruleset_name,
        "cui_detected": bool(cui_hits),
        "risk_level": risk,
        "risk_score": risk_score,
        "cui_categories": list(cui_hits.keys()),
        "sensitive_categories": list(sens_hits.keys()),
        "patterns_found": cui_hits,
        "sensitive_patterns_found": sens_hits,
        "keyword_triggers_hit": kw_hits,
        "recommended_actions": (
            ["Apply CUI markings and restrict access."]
            if cui_hits else
            ["No CUI detected; apply standard handling."]
        ),
    }

# =============================================================================
# Artifact helpers (Step 4)
# =============================================================================
def build_artifacts(meta: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, bytes]:
    payload = {
        "meta": meta,
        "analysis": analysis,
        "generated_at": now_iso(),
    }
    json_bytes = json.dumps(payload, indent=2).encode("utf-8")

    rows = [{
        "filename": meta["filename"],
        "sha256": meta["sha256"],
        "uploaded_at": meta["uploaded_at"],
        "ruleset": analysis["ruleset"],
        "risk_level": analysis["risk_level"],
        "risk_score": analysis["risk_score"],
        "cui_detected": analysis["cui_detected"],
        "cui_categories": ";".join(analysis["cui_categories"]),
        "sensitive_categories": ";".join(analysis["sensitive_categories"]),
    }]
    for k, v in analysis["patterns_found"].items():
        rows.append({"type": "cui_pattern", "pattern": k, "count": v})
    for k, v in analysis["sensitive_patterns_found"].items():
        rows.append({"type": "sensitive_pattern", "pattern": k, "count": v})

    df = pd.DataFrame(rows)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    return {
        "analysis_report.json": json_bytes,
        "analysis_summary.csv": csv_bytes,
    }

# =============================================================================
# Session State
# =============================================================================
for k in ["last_text", "last_meta", "last_analysis", "artifacts"]:
    if k not in st.session_state:
        st.session_state[k] = None

# =============================================================================
# Pages
# =============================================================================
if page == "Document Inspector":
    colA, colB = st.columns([1.2, 0.8], gap="large")

    with colA:
        uploaded = st.file_uploader("Upload a document", type=["pdf", "txt", "docx", "pptx"])
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

    with colB:
        st.subheader("Analysis Controls")
        ruleset_name = st.selectbox("Ruleset", list(RULESETS.keys()))
        st.caption(RULESETS[ruleset_name]["description"])

        if st.button("▶ Run Analysis", type="primary", disabled=not st.session_state.last_text):
            analysis = analyze_text(st.session_state.last_text, ruleset_name)
            st.session_state.last_analysis = analysis
            st.session_state.artifacts = build_artifacts(st.session_state.last_meta, analysis)

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
            for name, data in st.session_state.artifacts.items():
                st.download_button(
                    f"⬇ Download {name}",
                    data=data,
                    file_name=name,
                )

elif page == "System Info":
    st.header("System Info")
    st.write("Python:", sys.version)
    st.write("Platform:", platform.platform())
    st.write("OCR available:", OCR_AVAILABLE)




