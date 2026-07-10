from config import *
try:
    from config_local import *
except ImportError:
    pass


def evaluate(features: dict) -> dict:
    score = 0
    reasons = []
    threat = features.get("threat_context", {})
    brand = features.get("brand", {})

    if threat.get("urlhaus_hit"):
        score += 100
        reasons.append("URLhaus threat intelligence hit")
    if features["dga_score"] >= DGA_THRESHOLD:
        score += 30
        reasons.append("High DGA score")
    if (brand.get("matched_brand")
            and brand.get("match_type") != "official"
            and brand.get("confidence", 0.0) >= BRAND_MATCH_THRESHOLD):
        score += 25
        reasons.append(f"Brand similarity to {brand['matched_brand']}")
    if features["entropy"]["shannon"] >= ENTROPY_THRESHOLD:
        score += 20
        reasons.append("High entropy")
    if features["tld"]["suspicious_tld"]:
        score += 10
        reasons.append("Suspicious TLD")
    if features["digits"]["digit_ratio"] > 0.20:
        score += 5
        reasons.append("Excess digits")
    if features["hyphens"]["hyphen_count"] >= 2:
        score += 5
        reasons.append("Excess hyphens")
    if features["punycode"]["is_punycode"]:
        score += PUNYCODE_WEIGHT
        reasons.append("Punycode domain")
    age_days = features.get("age", {}).get("age_days")
    if age_days is not None:
        if age_days <= DOMAIN_AGE_NEW_DAYS:
            score += DOMAIN_AGE_NEW_WEIGHT
            reasons.append(f"Newly registered domain ({age_days} days old)")
        elif age_days <= DOMAIN_AGE_RECENT_DAYS:
            score += DOMAIN_AGE_RECENT_WEIGHT
            reasons.append(f"Recently registered domain ({age_days} days old)")

    if score >= 80:
        severity = "HIGH"
    elif score >= 50:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return {"rule_score": min(score, 100), "severity": severity, "rule_reasons": reasons}
