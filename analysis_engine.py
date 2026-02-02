import re
from utils import clamp
from rulesets import RULESETS


def analyze_text(text: str, ruleset_name: str):
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
