import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from features.extractor import extract
from features.lexical import registered_domain, hostname

# Brand maps are derived from the Tranco list at runtime; tests pass an
# explicit map so feature extraction stays deterministic and config-free.
_BRANDS = {"google": "google.com", "paypal": "paypal.com"}


def test_registered_domain_uses_public_suffix_list():
    assert registered_domain("onlinesbi.sbi.co.in") == "sbi.co.in"
    assert registered_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("foo.googleapis.com") == "googleapis.com"
    assert registered_domain("evil.com") == "evil.com"


def test_hostname_extracts_registrable_label_under_multipart_tld():
    assert hostname("onlinesbi.sbi.co.in") == "sbi"
    assert hostname("www.bbc.co.uk") == "bbc"
    assert hostname("mail.google.com") == "google"


def test_extract_returns_deterministic_feature_payload():
    features = extract("paypa1-login-security.xyz", brands=_BRANDS)

    assert features["domain"] == "paypa1-login-security.xyz"
    assert features["entropy"]["shannon"] > 0
    assert features["digits"]["digit_count"] == 1
    assert features["hyphens"]["hyphen_count"] == 2
    assert features["tld"]["suspicious_tld"] is True
    assert features["brand"]["matched_brand"] == "Paypal"
    assert features["rules"]["rule_score"] >= 40


def test_brand_official_domain_detected_as_official():
    from features.brand import detect
    result = detect("mail.google.com", brands=_BRANDS)
    assert result["matched_brand"] == "Google"
    assert result["match_type"] == "official"


def test_brand_owned_registered_domain_containing_brand_is_contains():
    from features.brand import detect
    result = detect("oauth2.googleapis.com", brands=_BRANDS)
    assert result["matched_brand"] == "Google"
    assert result["match_type"] == "contains"


def test_brand_leet_substitution_is_leet_not_exact():
    from features.brand import detect
    result = detect("g00gle.com", brands=_BRANDS)
    assert result["matched_brand"] == "Google"
    assert result["match_type"] == "leet"


def test_brand_in_hyphenated_label_is_embedded():
    from features.brand import detect
    result = detect("paypal-login.com", brands=_BRANDS)
    assert result["matched_brand"] == "Paypal"
    assert result["match_type"] == "embedded"


def test_brand_lookalike_is_fuzzy():
    from features.brand import detect
    result = detect("gooogle.com", brands=_BRANDS)
    assert result["matched_brand"] == "Google"
    assert result["match_type"] == "fuzzy"


def test_brand_no_match_nulls_all_fields():
    from features.brand import detect
    result = detect("example.org", brands=_BRANDS)
    assert result["matched_brand"] is None
    assert result["match_type"] is None
    assert result["confidence"] == 0.0


def test_official_brand_domain_adds_no_brand_rule_score():
    features = extract("mail.google.com", brands=_BRANDS)
    assert features["brand"]["match_type"] == "official"
    assert features["rules"]["rule_score"] == 0
    assert "Brand similarity" not in " ".join(features["rules"]["rule_reasons"])


def test_leet_brand_match_still_adds_rule_score():
    features = extract("g00gle.com", brands=_BRANDS)
    assert features["brand"]["match_type"] == "leet"
    assert features["rules"]["rule_score"] >= 25


def test_extract_includes_threat_context_in_rule_score():
    features = extract("evil.com", threat_context={"urlhaus_hit": True})

    assert features["threat_context"]["urlhaus_hit"] is True
    assert features["rules"]["rule_score"] == 100
    assert features["rules"]["severity"] == "HIGH"


def test_brand_detect_defaults_to_extra_brands_seed():
    from features.brand import detect
    result = detect("hdfc-netbanking-login.xyz")
    assert result["matched_brand"] == "Hdfc"
    assert result["match_type"] == "embedded"
