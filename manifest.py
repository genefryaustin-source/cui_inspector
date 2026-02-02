import io, zipfile
import pandas as pd
import streamlit as st
from db import db, init_db
from auth import tenant_id, audit
from repo import read_object

def render_manifest_export():
    st.header("📦 Evidence Export Manifest (FedRAMP / CMMC delivery)")
    tid = tenant_id()
    if tid is None:
        st.error("Select a tenant in the sidebar first.")
        return

    init_db()
    include_objects = st.toggle("Include evidence objects inside ZIP", value=False)

    if not st.button("Generate manifest ZIP", type="primary"):
        return

    with db() as con:
        rows = con.execute(
            """
            SELECT
                ef.id AS evidence_id,
                ef.inspection_id,
                ef.kind,
                ef.filename,
                ef.sha256,
                ef.size_bytes,
                ef.object_relpath,
                ef.created_at,
                i.started_at AS inspection_started_at,
                i.risk_level
            FROM evidence_files ef
            JOIN inspections i ON i.id = ef.inspection_id
            WHERE ef.tenant_id = ?
            ORDER BY ef.created_at DESC
            """,
            (tid,),
        ).fetchall()

    df = pd.DataFrame([dict(r) for r in rows])

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.csv", df.to_csv(index=False))

        hashes_txt = "\n".join(
            f"{row['sha256']}  {row['filename']}  {row['object_relpath']}"
            for _, row in df.iterrows()
        ) + "\n"

        z.writestr("hashes.sha256.txt", hashes_txt)

        if include_objects:
            for _, row in df.iterrows():
                try:
                    z.writestr(
                        f"repo/{row['object_relpath']}",
                        read_object(row["object_relpath"]),
                    )
                except Exception:
                    pass

    buf.seek(0)
    audit("export_manifest", {"rows": len(df), "include_objects": include_objects})

    st.download_button(
        "⬇️ Download manifest ZIP",
        data=buf.read(),
        file_name=f"evidence_manifest_tenant_{tid}.zip",
        mime="application/zip",
    )

