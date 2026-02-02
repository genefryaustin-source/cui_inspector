import json
import pandas as pd
import streamlit as st
from utils import now_iso


def build_artifacts(meta, analysis):
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


def artifacts_to_download_buttons(artifacts):
    if not artifacts:
        return

    for name, data in artifacts.items():
        st.download_button(
            f"⬇ Download {name}",
            data=data,
            file_name=name
        )

