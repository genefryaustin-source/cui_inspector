import json
import hashlib
import streamlit as st

from db import get_connection
from utils import now_iso


def save_inspection(meta, analysis, artifacts):
    con = get_connection()
    cur = con.cursor()

    cur.execute("""
        INSERT INTO inspections
        (filename, sha256, ruleset, risk_level, risk_score, analysis_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        meta["filename"],
        meta["sha256"],
        analysis["ruleset"],
        analysis["risk_level"],
        analysis["risk_score"],
        json.dumps(analysis),
        now_iso()
    ))

    inspection_id = cur.lastrowid

    for name, content in artifacts.items():
        h = hashlib.sha256(content).hexdigest()
        cur.execute("""
            INSERT INTO artifacts
            (inspection_id, name, sha256, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (inspection_id, name, h, content, now_iso()))

    con.commit()
    con.close()


def render_evidence_vault():
    st.header("📦 Evidence Vault")

    con = get_connection()
    rows = con.execute("""
        SELECT id, filename, risk_level, risk_score, created_at
        FROM inspections
        ORDER BY created_at DESC
    """).fetchall()

    if not rows:
        st.info("No inspections stored yet.")
        return

    for r in rows:
        with st.expander(
            f"#{r['id']} • {r['filename']} • {r['risk_level']} ({r['risk_score']})"
        ):
            st.caption(f"Created at: {r['created_at']}")

            analysis = json.loads(
                con.execute(
                    "SELECT analysis_json FROM inspections WHERE id=?",
                    (r["id"],)
                ).fetchone()[0]
            )
            st.json(analysis)

            arts = con.execute("""
                SELECT name, sha256, content
                FROM artifacts
                WHERE inspection_id=?
            """, (r["id"],)).fetchall()

            st.subheader("Artifacts")
            for a in arts:
                st.download_button(
                    f"⬇ Download {a['name']}",
                    data=a["content"],
                    file_name=a["name"]
                )

                recomputed = hashlib.sha256(a["content"]).hexdigest()
                if recomputed == a["sha256"]:
                    st.success("Hash verified")
                else:
                    st.error("Hash mismatch")

    con.close()

