import json
import re
import streamlit as st
from db import db, now_iso
from repo import write_object
from auth import tenant_id, current_user, audit, is_auditor

PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "dod_edipi": r"\b\d{10}\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "phone": r"\b(?:\+1\s*)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "cage_code": r"\b[A-HJ-NP-Z0-9]{5}\b",
    "contract": r"\b(FA\w{2}\d{2}-\w-\d{5}|W\d{2}\w{2}\w{2}\d{2}\w\d{4})\b",
}

CATEGORIES = {
    "PII": ["ssn", "email", "phone"],
    "DoD Identifiers": ["dod_edipi"],
    "Contracting": ["contract", "cage_code"],
}

def _extract_text(filename: str, data: bytes) -> str:
    name = filename.lower()
    if name.endswith(".txt"):
        return data.decode("utf-8", errors="ignore")
    if name.endswith(".pdf"):
        try:
            import PyPDF2
            from io import BytesIO
            reader = PyPDF2.PdfReader(BytesIO(data))
            out = []
            for p in reader.pages[:20]:
                out.append(p.extract_text() or "")
            return "\n".join(out)
        except Exception:
            return ""
    if name.endswith(".docx"):
        try:
            import docx
            from io import BytesIO
            d = docx.Document(BytesIO(data))
            return "\n".join([p.text for p in d.paragraphs])
        except Exception:
            return ""
    return ""

def analyze_text(text: str):
    found = {}
    for k, pat in PATTERNS.items():
        matches = re.findall(pat, text)
        if matches:
            found[k] = len(matches)

    categories = []
    for cat, keys in CATEGORIES.items():
        total = sum(found.get(k, 0) for k in keys)
        if total > 0:
            categories.append({"category": cat, "hits": total})

    total_hits = sum(found.values())
    cui_detected = 1 if total_hits > 0 else 0

    if total_hits == 0:
        risk = "NONE"
    elif total_hits <= 3:
        risk = "LOW"
    elif total_hits <= 15:
        risk = "MODERATE"
    else:
        risk = "HIGH"

    summary = {
        "total_hits": total_hits,
        "top_patterns": sorted(found.items(), key=lambda x: x[1], reverse=True)[:5],
        "notes": "Lightweight pattern scan. Treat as screening, not a formal determination.",
        "recommendations": [
            "Apply CUI markings if applicable.",
            "Store/transmit only in approved enclaves.",
            "Enforce access control + audit logging.",
        ],
    }

    return {
        "cui_detected": cui_detected,
        "risk_level": risk,
        "patterns": found,
        "categories": categories,
        "summary": summary,
    }

def upsert_artifact_version(tid: int, filename: str, data: bytes, mime: str, uploaded_by: str):
    logical = filename
    sha, rel, size = write_object(data)

    with db() as con:
        row = con.execute("SELECT id FROM artifacts WHERE tenant_id=? AND logical_name=?", (tid, logical)).fetchone()
        if row:
            artifact_id = int(row["id"])
        else:
            con.execute("INSERT INTO artifacts (tenant_id, logical_name, created_at) VALUES (?,?,?)", (tid, logical, now_iso()))
            artifact_id = int(con.execute("SELECT id FROM artifacts WHERE tenant_id=? AND logical_name=?", (tid, logical)).fetchone()["id"])

        cur = con.execute(
            "SELECT COALESCE(MAX(version_int),0) AS v FROM artifact_versions WHERE tenant_id=? AND artifact_id=?",
            (tid, artifact_id),
        ).fetchone()
        next_ver = int(cur["v"]) + 1

        con.execute(
            "INSERT INTO artifact_versions (tenant_id, artifact_id, version_int, original_filename, object_relpath, sha256, size_bytes, mime, created_at, uploaded_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tid, artifact_id, next_ver, filename, rel, sha, size, mime, now_iso(), uploaded_by),
        )
        av_id = int(con.execute("SELECT id FROM artifact_versions WHERE tenant_id=? AND artifact_id=? AND version_int=?", (tid, artifact_id, next_ver)).fetchone()["id"])
    return av_id

def save_inspection_record(tid: int, artifact_version_id: int, findings: dict, started_at: str, finished_at: str):
    with db() as con:
        con.execute(
            "INSERT INTO inspections (tenant_id, artifact_version_id, run_type, started_at, finished_at, cui_detected, risk_level, patterns_json, categories_json, summary_json, error) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                tid, artifact_version_id, "single", started_at, finished_at,
                int(findings.get("cui_detected") or 0),
                findings.get("risk_level"),
                json.dumps(findings.get("patterns") or {}),
                json.dumps(findings.get("categories") or []),
                json.dumps(findings.get("summary") or {}),
            ),
        )
        return int(con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])

def attach_evidence_file(tid: int, inspection_id: int, kind: str, filename: str, data: bytes):
    sha, rel, size = write_object(data)
    with db() as con:
        con.execute(
            "INSERT INTO evidence_files (tenant_id, inspection_id, kind, filename, object_relpath, sha256, size_bytes, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (tid, inspection_id, kind, filename, rel, sha, size, now_iso()),
        )
        return int(con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])

def save_text_index(tid: int, inspection_id: int, artifact_version_id: int, filename: str, text: str, findings: dict):
    excerpt = (text or "")[:1200]
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    words = len((text or "").split())
    chars = len(text or "")
    patterns_total = sum((findings.get("patterns") or {}).values()) if findings else 0
    with db() as con:
        con.execute(
            "INSERT INTO inspection_text_index (tenant_id, inspection_id, artifact_version_id, filename, file_ext, safe_excerpt, char_count, word_count, patterns_total, categories_json, risk_level, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tid, inspection_id, artifact_version_id, filename, ext, excerpt, chars, words, int(patterns_total),
                json.dumps(findings.get("categories") or []),
                findings.get("risk_level"),
                now_iso(),
            ),
        )

def render_inspector():
    st.header("🧪 Inspect Document")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return

    if is_auditor():
        st.info("Auditor role: intended for review/verification.")

    uploaded = st.file_uploader("Upload a document (PDF/DOCX/TXT)", type=["pdf", "docx", "txt"])
    store_index = st.toggle("Store safe excerpt for search", value=True)

    if not uploaded:
        return

    file_bytes = uploaded.read()
    started = now_iso()
    mime = uploaded.type or "application/octet-stream"
    u = current_user()
    uploader = u["username"] if u else "unknown"

    text = _extract_text(uploaded.name, file_bytes)
    findings = analyze_text(text)
    finished = now_iso()

    av_id = upsert_artifact_version(int(tid), uploaded.name, file_bytes, mime, uploader)
    ins_id = save_inspection_record(int(tid), av_id, findings, started, finished)

    attach_evidence_file(int(tid), ins_id, "findings_json", "findings.json", json.dumps(findings, indent=2).encode("utf-8"))

    if store_index:
        save_text_index(int(tid), ins_id, av_id, uploaded.name, text, findings)

    audit("inspection_run", {"inspection_id": ins_id, "artifact_version_id": av_id, "risk_level": findings.get("risk_level")})

    st.success(f"Inspection saved (ID {ins_id}). Risk: {findings.get('risk_level')}")
    st.json(findings)
