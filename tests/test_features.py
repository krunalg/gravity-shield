import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from features.extractor import extract


def test_extract_returns_deterministic_feature_payload():
    features = extract("paypa1-login-security.xyz")

    assert features["domain"] == "paypa1-login-security.xyz"
    assert features["entropy"]["shannon"] > 0
    assert features["digits"]["digit_count"] == 1
    assert features["hyphens"]["hyphen_count"] == 2
    assert features["tld"]["suspicious_tld"] is True
    assert features["brand"]["matched_brand"] == "Paypal"
    assert features["rules"]["rule_score"] >= 40


def test_extract_includes_threat_context_in_rule_score():
    features = extract("evil.com", threat_context={"urlhaus_hit": True})

    assert features["threat_context"]["urlhaus_hit"] is True
    assert features["rules"]["rule_score"] == 100
    assert features["rules"]["severity"] == "HIGH"
