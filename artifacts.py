import json
from typing import Dict, Any
import pandas as pd
import streamlit as st
from utils import now_iso

def build_artifacts(meta: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, bytes]:
    payload = {
        "meta": meta,
        "analysis": analysis,
        "generated_at": now_iso(),
    }
    json_bytes = json.dumps(payload, indent=2).encode("utf-8")

    rows = [{
        "filename": meta.get("filename", ""),
        "sha256": meta.get("sha256", ""),
        "uploaded_at": meta.get("uploaded_at", ""),
        "ruleset": analysis.get("ruleset", ""),
        "risk_level": analysis.get("risk_level", ""),
        "risk_score": analysis.get("risk_score", ""),
        "cui_detected": analysis.get("cui_detected", ""),
        "cui_categories": ";".join(analysis.get("cui_categories", [])),
        "sensitive_categories": ";".join(analysis.get("sensitive_categories", [])),
        "keyword_triggers_hit": ";".join(analysis.get("keyword_triggers_hit", [])),
    }]

    for k, v in (analysis.get("patterns_found") or {}).items():
        rows.append({"type": "cui_pattern", "pattern": k, "count": v})
    for k, v in (analysis.get("sensitive_patterns_found") or {}).items():
        rows.append({"type": "sensitive_pattern", "pattern": k, "count": v})

    df = pd.DataFrame(rows)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    return {
        "analysis_report.json": json_bytes,
        "analysis_summary.csv": csv_bytes,
    }

def artifacts_to_download_buttons(artifacts: Dict[str, bytes] | None) -> None:
    if not artifacts:
        st.caption("Run analysis to generate artifacts.")
        return
    for name, data in artifacts.items():
        st.download_button(
            f"⬇ Download {name}",
            data=data,
            file_name=name,
        )
