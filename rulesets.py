RULESETS = {
    "Basic": {
        "description": "Balanced detection. Email is sensitive, not CUI.",
        "cui_patterns": {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "DoD_ID": r"\b\d{10}\b",
        },
        "sensitive_patterns": {
            "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        },
        "keywords": ["controlled unclassified information", "cui", "fouo"],
        "weights": {"cui": 20, "sensitive": 5, "keyword": 8, "multi_bonus": 10},
    },
    "DoD / GovCon": {
        "description": "Stricter profile for defense contractors.",
        "cui_patterns": {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "DoD_ID": r"\b\d{10}\b",
            "CAGE": r"\b[A-HJ-NP-Z0-9]{5}\b",
        },
        "sensitive_patterns": {
            "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        },
        "keywords": ["itar", "ear", "dfars", "export controlled"],
        "weights": {"cui": 25, "sensitive": 5, "keyword": 10, "multi_bonus": 15},
    },
}


def ruleset_names():
    return list(RULESETS.keys())

