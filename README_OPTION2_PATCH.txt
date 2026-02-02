Option 2 Upgrade Patch (CUI Analysis)
====================================

This patch restores and upgrades the original CUI inspection experience:
- Detection signals (why flagged)
- Pattern counts + excerpts
- CUI category inference with confidence
- CMMC/NIST/FedRAMP guidance and mapping
- Richer artifacts:
  - cui_findings.json
  - compliance_mapping.json
  - recommendations.txt

Apply:
1) Replace analysis_engine.py
2) Replace rulesets.py
3) Replace artifacts.py
4) Replace render_document_inspector() in ui.py with the function in ui_render_document_inspector_option2.py

No schema changes required.
