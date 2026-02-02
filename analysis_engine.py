import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any

from utils import clamp
from rulesets import RULESETS

# -----------------------------
# Option 2: Upgraded analysis
# -----------------------------

@dataclass
class Hit:
    kind: str              # "pattern" | "keyword" | "context" | "absence"
    name: str              # rule/pattern name
    excerpt: str           # short excerpt
    count: int = 1
    confidence: float = 0.75
    category: str | None = None


def _snip(text: str, start: int, end: int, pad: int = 60) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    snippet = text[s:e].replace("\n", " ").strip()
    return snippet[:240] + ("…" if len(snippet) > 240 else "")


def _regex_hits(text: str, name: str, pattern: str, flags=re.IGNORECASE) -> Tuple[int, List[str]]:
    hits = []
    for m in re.finditer(pattern, text, flags):
        hits.append(_snip(text, m.start(), m.end()))
    return len(hits), hits[:8]  # cap stored excerpts


def _contains_any(tlow: str, phrases: List[str]) -> List[str]:
    return [p for p in phrases if p in tlow]


def analyze_text(text: str, ruleset_name: str) -> Dict[str, Any]:
    """Returns an auditor-friendly analysis object.

    IMPORTANT: This intentionally avoids storing the full document text in DB.
    Only short excerpts/snippets are stored.
    """
    rs = RULESETS[ruleset_name]
    t = text or ""
    tlow = t.lower()

    hits: List[Hit] = []

    # 1) Explicit CUI / markings signals
    explicit_marking_phrases = rs.get("explicit_markings", [])
    explicit_found = _contains_any(tlow, explicit_marking_phrases)
    if explicit_found:
        for p in explicit_found[:8]:
            idx = tlow.find(p)
            hits.append(Hit(kind="keyword", name="explicit_marking",
                            excerpt=_snip(t, idx, idx + len(p)),
                            confidence=0.92, category="Explicitly Marked CUI"))

    # 2) Context / handling language signals (even if markings missing)
    context_phrases = rs.get("context_phrases", [])
    ctx_found = _contains_any(tlow, context_phrases)
    if ctx_found:
        for p in ctx_found[:10]:
            idx = tlow.find(p)
            hits.append(Hit(kind="context", name="handling_context",
                            excerpt=_snip(t, idx, idx + len(p)),
                            confidence=0.80, category="Handling / Dissemination"))

    # 3) Rule-based patterns (regex)
    patterns_found: Dict[str, int] = {}
    detected_patterns: List[Dict[str, Any]] = []
    cui_categories: Dict[str, float] = {}  # category -> confidence

    for pname, pdef in rs["patterns"].items():
        cnt, snippets = _regex_hits(t, pname, pdef["regex"])
        if cnt:
            patterns_found[pname] = cnt
            cat = pdef.get("category")
            conf = float(pdef.get("confidence", 0.78))
            if cat:
                cui_categories[cat] = max(cui_categories.get(cat, 0.0), conf)
            for sn in snippets:
                detected_patterns.append({
                    "pattern": pname,
                    "category": cat,
                    "confidence": conf,
                    "excerpt": sn,
                })
                hits.append(Hit(kind="pattern", name=pname, excerpt=sn,
                                confidence=conf, category=cat))

    # 4) Absence-of-controls heuristic:
    missing_markings = (not explicit_found) and bool(ctx_found or patterns_found)
    if missing_markings:
        hits.append(Hit(kind="absence", name="missing_markings",
                        excerpt="Document contains handling/dissemination indicators without explicit CUI markings.",
                        confidence=0.78, category="Missing Markings"))

    # 5) Keyword triggers (legacy)
    kw_hits = []
    for kw in rs.get("keywords", []):
        if kw in tlow:
            kw_hits.append(kw)
            idx = tlow.find(kw)
            hits.append(Hit(kind="keyword", name="keyword_trigger",
                            excerpt=_snip(t, idx, idx + len(kw)),
                            confidence=0.72, category="Keyword Trigger"))

    # --- Scoring model ---
    weights = rs["weights"]
    score = 0.0
    score += len(explicit_found) * weights["explicit_marking"]
    score += min(len(ctx_found), 12) * weights["context"]
    score += sum(patterns_found.values()) * weights["pattern"]
    if missing_markings:
        score += weights["missing_markings_bonus"]
    score += len(kw_hits) * weights["keyword"]
    if len(cui_categories) >= 2:
        score += weights["multi_category_bonus"]

    risk_score = int(clamp(score, 0, 100))
    risk_level = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 30 else "LOW"

    cui_detected = bool(explicit_found or patterns_found or (ctx_found and missing_markings))

    recommendations, compliance_map = _build_recommendations_and_mapping(
        cui_detected=cui_detected,
        risk_level=risk_level,
        risk_score=risk_score,
        categories=list(cui_categories.keys()),
        missing_markings=missing_markings
    )

    signals = []
    if explicit_found:
        signals.append("Explicit CUI context / markings present")
    if ctx_found:
        signals.append("Handling/dissemination context present")
    if patterns_found:
        signals.append("Structured patterns detected")
    if missing_markings:
        signals.append("Missing required markings (heuristic)")
    if not signals:
        signals.append("No strong indicators detected")

    categories_sorted = [
        {"category": c, "confidence": round(cui_categories[c], 2)}
        for c in sorted(cui_categories.keys(), key=lambda x: cui_categories[x], reverse=True)
    ]

    hits_compact = [{
        "kind": h.kind,
        "name": h.name,
        "category": h.category,
        "confidence": round(h.confidence, 2),
        "excerpt": h.excerpt
    } for h in hits[:40]]

    return {
        "ruleset": ruleset_name,
        "cui_detected": bool(cui_detected),
        "risk_level": risk_level,
        "risk_score": risk_score,

        "signals": signals,
        "patterns_found": patterns_found,
        "detected_patterns": detected_patterns,
        "cui_categories": categories_sorted,

        "keyword_triggers_hit": kw_hits,
        "missing_markings_heuristic": bool(missing_markings),

        "recommendations": recommendations,
        "compliance_mapping": compliance_map,

        "hits": hits_compact
    }


def _build_recommendations_and_mapping(*, cui_detected: bool, risk_level: str, risk_score: int,
                                      categories: List[str], missing_markings: bool):
    recs: List[str] = []
    cmmc: List[Dict[str, str]] = []
    nist171: List[Dict[str, str]] = []
    fedramp: List[Dict[str, str]] = []

    if cui_detected:
        recs.append("Apply appropriate CUI markings per NARA CUI Registry and organizational marking standard.")
        recs.append("Restrict access to authorized users and enforce least privilege for all CUI repositories.")
        recs.append("Ensure encryption in transit (TLS 1.2+) for any CUI transfer channels.")
        recs.append("Ensure encryption at rest for CUI stored in file shares, object storage, and backups.")
        recs.append("Document CUI handling scope, boundary, and controls in the SSP; update data flow diagrams.")
        recs.append("Enable and retain audit logs for CUI access, changes, downloads, and sharing events.")

        if missing_markings:
            recs.insert(1, "Add missing markings and dissemination controls; prohibit sharing until reclassified/marked.")

        if risk_level == "HIGH":
            recs.insert(0, "Treat as high-risk CUI exposure: quarantine distribution and initiate incident review.")

        cmmc.extend([
            {"control": "AC.1.001", "title": "Limit system access to authorized users"},
            {"control": "AC.3.018", "title": "Encrypt CUI at rest"},
            {"control": "SC.3.177", "title": "Encrypt CUI in transit"},
            {"control": "AU.2.041", "title": "Audit and accountability (logging)"},
        ])

        nist171.extend([
            {"control": "3.1.1", "title": "Limit system access to authorized users"},
            {"control": "3.13.8", "title": "Implement cryptographic protections for CUI"},
            {"control": "3.3.1", "title": "Create and retain system audit logs"},
        ])

        fedramp.extend([
            {"control": "AC-2", "title": "Account management (authorized users)"},
            {"control": "SC-13", "title": "Cryptographic protection"},
            {"control": "AU-2", "title": "Event logging"},
        ])
    else:
        recs.append("No strong CUI indicators detected. Apply standard information handling and validate classification.")
        if risk_score > 0:
            recs.append("Review sensitive indicators and ensure appropriate access controls and retention policies.")

    compliance_map = {
        "CMMC_Level_2": cmmc,
        "NIST_SP_800_171": nist171,
        "FedRAMP_Moderate": fedramp,
        "notes": [
            "Mappings are guidance aids; validate applicability to your system boundary and contract requirements."
        ]
    }
    return recs, compliance_map
