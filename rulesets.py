RULESETS = {
    "Basic": {
        "description": "Balanced detection. Email is sensitive, not CUI.",
        "explicit_markings": [
            "controlled unclassified information",
            "cui",
            "cui//",
            "fouo",
            "for official use only",
        ],
        "context_phrases": [
            "improper dissemination",
            "unauthorized sharing",
            "missing markings",
            "do not distribute",
            "distribution statement",
            "export controlled",
            "limited dissemination",
            "need to know",
        ],
        "patterns": {
            "SSN": {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "category": "CUI//SP-PRIV (privacy)", "confidence": 0.90},
            "DoD_ID": {"regex": r"\b\d{10}\b", "category": "CUI//SP-PRIV (identifier)", "confidence": 0.78},
        },
        "keywords": ["itar", "ear", "dfars", "nara cui registry"],
        "weights": {
            "explicit_marking": 16,
            "context": 6,
            "pattern": 18,
            "keyword": 5,
            "missing_markings_bonus": 14,
            "multi_category_bonus": 10
        },
    },
    "DoD / GovCon": {
        "description": "Stricter profile for defense contractors.",
        "explicit_markings": [
            "controlled unclassified information",
            "cui",
            "cui//",
            "fouo",
            "for official use only",
            "distribution statement",
        ],
        "context_phrases": [
            "improper handling",
            "improper dissemination",
            "unauthorized sharing",
            "unauthorized disclosure",
            "missing markings",
            "do not distribute",
            "controlled by",
            "need to know",
            "third party",
            "export controlled",
            "dissemination",
            "releasable to",
        ],
        "patterns": {
            "SSN": {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "category": "CUI//SP-PRIV (privacy)", "confidence": 0.92},
            "CAGE": {"regex": r"\b[A-HJ-NP-Z0-9]{5}\b", "category": "CUI//SP-ORG (org id)", "confidence": 0.70},
            "ITAR": {"regex": r"\bITAR\b", "category": "CUI//SP-EXPT (export)", "confidence": 0.78},
            "EAR": {"regex": r"\bEAR\b", "category": "CUI//SP-EXPT (export)", "confidence": 0.72},
            "CTI": {"regex": r"\b(threat indicator|ioc|indicator of compromise)\b", "category": "CUI//SP-CTI (cyber threat)", "confidence": 0.75},
        },
        "keywords": ["itar", "ear", "dfars", "cmmc", "nist 800-171", "nara"],
        "weights": {
            "explicit_marking": 18,
            "context": 8,
            "pattern": 20,
            "keyword": 6,
            "missing_markings_bonus": 16,
            "multi_category_bonus": 12
        },
    },
}

def ruleset_names():
    return list(RULESETS.keys())
