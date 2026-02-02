import json, os, re
import streamlit as st
from db import db, init_db, now_iso
from repo import write_object
from auth import tenant_id, current_user, audit
from legacy_components import CUIInspector

def _logical(filename: str) -> str:
    base = os.path.basename(filename or "document")
    return re.sub(r"\s+"," ", base).strip().lower()

def upsert_artifact_version(tid: int, filename: str, data: bytes, mime: str, uploaded_by: str):
    init_db()
    logical = _logical(filename)
    sha, rel, size = write_object(data)
    with db() as con:
        a = con.execute("SELECT id FROM artifacts WHERE tenant_id=? AND logical_name=?", (tid, logical)).fetchone()
        if a:
            artifact_id = int(a["id"])
        else:
            con.execute("INSERT INTO artifacts (tenant_id, logical_name, created_at) VALUES (?,?,?)", (tid, logical, now_iso()))
            artifact_id = int(con.execute("SELECT id FROM artifacts WHERE tenant_id=? AND logical_name=?", (tid, logical)).fetchone()["id"])

        last = con.execute(
            "SELECT id, version_int, sha256 FROM artifact_versions WHERE tenant_id=? AND artifact_id=? ORDER BY version_int DESC LIMIT 1",
            (tid, artifact_id),
        ).fetchone()
        if last and last["sha256"] == sha:
            return int(last["id"])

        next_ver = 1 if not last else int(last["version_int"]) + 1
        con.execute(
            "INSERT INTO artifact_versions (tenant_id,artifact_id,version_int,original_filename,object_relpath,sha256,size_bytes,mime,created_at,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tid, artifact_id, next_ver, filename, rel, sha, size, mime, now_iso(), uploaded_by),
        )
        con.commit()
        return int(con.execute(
            "SELECT id FROM artifact_versions WHERE tenant_id=? AND artifact_id=? AND version_int=?",
            (tid, artifact_id, next_ver),
        ).fetchone()["id"])

def save_inspection_record(tid: int, artifact_version_id, run_type: str, findings: dict, started_at: str, finished_at: str):
    init_db()
    with db() as con:
        con.execute(
            "INSERT INTO inspections (tenant_id,artifact_version_id,run_type,started_at,finished_at,cui_detected,risk_level,patterns_json,categories_json,summary_json,error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                tid, artifact_version_id, run_type, started_at, finished_at,
                None if findings.get("cui_detected") is None else (1 if findings.get("cui_detected") else 0),
                findings.get("risk_level"),
                json.dumps(findings.get("patterns_found") or {}),
                json.dumps(findings.get("cui_categories") or []),
                json.dumps(findings),
                findings.get("error"),
            ),
        )
        ins_id = int(con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])
        con.commit()
        return ins_id

def attach_evidence_file(tid: int, inspection_id: int, kind: str, filename: str, data: bytes):
    sha, rel, size = write_object(data)
    with db() as con:
        con.execute(
            "INSERT INTO evidence_files (tenant_id,inspection_id,kind,filename,object_relpath,sha256,size_bytes,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (tid, inspection_id, kind, filename, rel, sha, size, now_iso()),
        )
        con.commit()

def save_text_index(tid: int, inspection_id: int, artifact_version_id, filename: str, text: str, findings: dict, store_excerpt: bool):
    excerpt = (text or "")[:1200] if store_excerpt else ""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    patterns_total = 0
    try:
        patterns_total = int(sum((findings.get("patterns_found") or {}).values()))
    except Exception:
        patterns_total = 0

    with db() as con:
        con.execute(
            "INSERT INTO inspection_text_index (tenant_id,inspection_id,artifact_version_id,filename,file_ext,safe_excerpt,char_count,word_count,patterns_total,categories_json,risk_level,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tid, inspection_id, artifact_version_id, filename, ext, excerpt,
                len(text or ""), len((text or "").split()), patterns_total,
                json.dumps(findings.get("cui_categories") or []),
                findings.get("risk_level"),
                now_iso(),
            ),
        )
        con.commit()

def render_cui_inspector():
    st.header("📄 CUI Document Inspector (Full)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return

    inspector = CUIInspector()
    autosave = st.toggle("Auto-save evidence (JSON + PDF)", value=True)
    store_index = st.toggle("Enable search index", value=True)
    store_excerpt = st.toggle("Store safe excerpt (optional)", value=True, help="If off, search becomes metadata-only.")
    uploaded_by = st.text_input("Uploaded/Run by (optional)", value=(current_user() or {}).get("username",""))

    files = st.file_uploader("Upload documents", accept_multiple_files=True)
    with st.expander("📝 Or paste text", expanded=False):
        manual_text = st.text_area("Paste text", height=180)
        manual_name = st.text_input("Name", value="manual_input.txt")

    if st.button("🔍 Inspect", type="primary"):
        results = []
        if files:
            for f in files:
                data = f.read()
                started = now_iso()
                findings = inspector.inspect_file(f.name, data)
                finished = now_iso()

                av_id = upsert_artifact_version(int(tid), f.name, data, getattr(f, "type", None) or "application/octet-stream", uploaded_by)
                ins_id = save_inspection_record(int(tid), av_id, "file", findings, started, finished)

                if autosave:
                    attach_evidence_file(int(tid), ins_id, "findings_json", f"findings_{ins_id}.json", json.dumps(findings, indent=2).encode("utf-8"))
                    try:
                        pdf = inspector.generate_cui_report_pdf(findings)
                        attach_evidence_file(int(tid), ins_id, "report_pdf", f"cui_report_{ins_id}.pdf", pdf)
                    except Exception:
                        pass

                if store_index:
                    try:
                        text = inspector.extract_text_from_file(f.name, data)
                    except Exception:
                        text = ""
                    save_text_index(int(tid), ins_id, av_id, f.name, text, findings, store_excerpt)

                audit("inspection_run", {"inspection_id": ins_id, "risk_level": findings.get("risk_level"), "filename": f.name})
                results.append((findings, ins_id))

        if manual_text:
            started = now_iso()
            findings = inspector.inspect_text(manual_text, manual_name)
            finished = now_iso()
            ins_id = save_inspection_record(int(tid), None, "manual", findings, started, finished)

            if autosave:
                attach_evidence_file(int(tid), ins_id, "findings_json", f"findings_{ins_id}.json", json.dumps(findings, indent=2).encode("utf-8"))
                try:
                    pdf = inspector.generate_cui_report_pdf(findings)
                    attach_evidence_file(int(tid), ins_id, "report_pdf", f"cui_report_{ins_id}.pdf", pdf)
                except Exception:
                    pass

            if store_index:
                save_text_index(int(tid), ins_id, None, manual_name, manual_text, findings, store_excerpt)

            audit("inspection_run", {"inspection_id": ins_id, "risk_level": findings.get("risk_level"), "filename": manual_name})
            results.append((findings, ins_id))

        if not results:
            st.warning("No inputs to inspect.")
            return

        st.success(f"Inspected {len(results)} item(s).")
        for findings, ins_id in results:
            with st.expander(f"{findings.get('filename')} (inspection #{ins_id})", expanded=True):
                st.json(findings)
