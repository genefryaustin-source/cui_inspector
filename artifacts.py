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
    analysis_json = json.dumps(payload, indent=2).encode("utf-8")

    findings = {
        "inspection": {
            "filename": meta.get("filename"),
            "sha256": meta.get("sha256"),
            "uploaded_at": meta.get("uploaded_at"),
            "ruleset": analysis.get("ruleset"),
            "risk_level": analysis.get("risk_level"),
            "risk_score": analysis.get("risk_score"),
            "cui_detected": analysis.get("cui_detected"),
        },
        "signals": analysis.get("signals", []),
        "cui_categories": analysis.get("cui_categories", []),
        "detected_patterns": analysis.get("detected_patterns", []),
        "recommendations": analysis.get("recommendations", []),
        "compliance_mapping": analysis.get("compliance_mapping", {}),
    }
    findings_json = json.dumps(findings, indent=2).encode("utf-8")

    mapping_json = json.dumps(analysis.get("compliance_mapping", {}), indent=2).encode("utf-8")

    rows = [{
        "filename": meta.get("filename"),
        "sha256": meta.get("sha256"),
        "uploaded_at": meta.get("uploaded_at"),
        "ruleset": analysis.get("ruleset"),
        "risk_level": analysis.get("risk_level"),
        "risk_score": analysis.get("risk_score"),
        "cui_detected": analysis.get("cui_detected"),
        "missing_markings_heuristic": analysis.get("missing_markings_heuristic"),
        "cui_categories": ";".join([c["category"] for c in analysis.get("cui_categories", [])]),
    }]

    for dp in analysis.get("detected_patterns", [])[:200]:
        rows.append({
            "type": "pattern_hit",
            "pattern": dp.get("pattern"),
            "category": dp.get("category"),
            "confidence": dp.get("confidence"),
            "excerpt": dp.get("excerpt"),
        })

    df = pd.DataFrame(rows)
    summary_csv = df.to_csv(index=False).encode("utf-8")

    rec_lines = ["CUI Inspector Recommendations", "==========================", ""]
    for i, r in enumerate(analysis.get("recommendations", []), 1):
        rec_lines.append(f"{i}. {r}")
    rec_txt = ("\n".join(rec_lines) + "\n").encode("utf-8")

    return {
        "analysis_report.json": analysis_json,
        "cui_findings.json": findings_json,
        "compliance_mapping.json": mapping_json,
        "analysis_summary.csv": summary_csv,
        "recommendations.txt": rec_txt,
    }


def artifacts_to_download_buttons(artifacts):
    if not artifacts:
        return

    prefix = "artifact_dl"
    for idx, (name, data) in enumerate(artifacts.items()):
        st.download_button(
            label=f"⬇ Download {name}",
            data=data,
            file_name=name,
            key=f"{prefix}_{idx}_{name}"
        )
