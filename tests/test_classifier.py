import os, sys, json
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import classifier

def _make_client(response_text: str):
    mock = MagicMock()
    mock.generate.return_value = response_text
    return mock

def test_classify_malware_domain():
    client = _make_client(
        '{"classification": "MALWARE", "confidence": 0.95, "severity": "HIGH", '
        '"risk_score": 91, "reasons": ["C2 beacon pattern"], "recommended_action": "BLOCK"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("evil-c2-beacon.ru")
    assert result.category == "MALWARE"
    assert result.confidence == 0.95
    assert result.should_block is True
    assert result.risk_score == 91

def test_classify_safe_domain():
    client = _make_client('{"category": "SAFE", "confidence": 0.99, "reason": "Legitimate CDN"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("cdn.example.com")
    assert result.category == "SAFE"
    assert result.should_block is False

def test_classify_low_confidence_not_blocked():
    client = _make_client(
        '{"classification": "MALWARE", "confidence": 0.60, "severity": "HIGH", '
        '"risk_score": 91, "reasons": ["uncertain"], "recommended_action": "BLOCK"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("maybe-bad.com")
    assert result.category == "MALWARE"
    assert result.should_block is False

def test_classify_handles_malformed_json():
    client = _make_client("I cannot classify this domain.")
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("weird.com")
    assert result.category == "UNKNOWN"
    assert result.should_block is False

def test_classify_handles_none_response():
    client = _make_client(None)
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("offline.com")
    assert result.category == "UNKNOWN"
    assert result.should_block is False

def test_classify_phishing_blocked():
    client = _make_client(
        '{"classification": "PHISHING", "confidence": 0.88, "severity": "HIGH", '
        '"risk_score": 90, "reasons": ["fake bank"], "recommended_action": "BLOCK"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("secure-hdfc-login.xyz")
    assert result.should_block is True

def test_recommended_allow_prevents_block_even_for_malware_category():
    client = _make_client(
        '{"classification": "MALWARE", "confidence": 0.99, "severity": "HIGH", '
        '"risk_score": 100, "reasons": ["feed hit"], "recommended_action": "ALLOW"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("important.example.com")

    assert result.category == "MALWARE"
    assert result.should_block is False

def test_prompt_sends_brand_match_type_and_guidance():
    client = _make_client('{"category": "SAFE", "confidence": 0.9, "reason": "ok"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    clf.classify("g00gle.com", brands={"google": "google.com"})
    prompt_sent = client.generate.call_args[0][0]
    assert '"brand_match_type": "leet"' in prompt_sent
    # Prompt must explain every match_type the evidence can contain
    for mtype in ("official", "exact", "contains", "embedded", "leet", "fuzzy"):
        assert f'brand_match_type="{mtype}"' in prompt_sent

def test_prompt_contains_domain():
    client = _make_client('{"category": "SAFE", "confidence": 0.9, "reason": "ok"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    clf.classify("targetdomain.com")
    prompt_sent = client.generate.call_args[0][0]
    assert "targetdomain.com" in prompt_sent
    assert "entropy_shannon" in prompt_sent
    assert "rule_score" in prompt_sent
    assert "dga_score" in prompt_sent


def test_classify_accepts_runtime_brand_map():
    client = _make_client('{"category": "SAFE", "confidence": 0.9, "reason": "ok"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    clf.classify("paypa1-secure.xyz", brands={"paypal": "paypal.com"})
    prompt_sent = client.generate.call_args[0][0]
    assert '"brand_match": "Paypal"' in prompt_sent


def test_block_gate_uses_deterministic_rule_score_not_llm_risk_score():
    """LLM risk_score is advisory — a lowballed LLM risk_score must not veto a
    block when deterministic evidence passes the floor."""
    client = _make_client(
        '{"classification": "MALWARE", "confidence": 0.95, "severity": "HIGH", '
        '"risk_score": 5, "reasons": ["c2"], "recommended_action": "BLOCK"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    # evil-c2-beacon.ru: .ru TLD +10, 2 hyphens +5 → deterministic rule_score 15
    result = clf.classify("evil-c2-beacon.ru")
    assert result.should_block is True


def test_no_block_when_deterministic_rule_score_below_floor():
    """LLM cannot force a block when deterministic features show nothing."""
    client = _make_client(
        '{"classification": "MALWARE", "confidence": 0.99, "severity": "HIGH", '
        '"risk_score": 95, "reasons": ["hallucinated"], "recommended_action": "BLOCK"}'
    )
    clf = classifier.DomainClassifier(ollama_client=client)
    # maybe-bad.com: deterministic rule_score 0 — below BLOCK_RULE_SCORE_FLOOR
    result = clf.classify("maybe-bad.com")
    assert result.should_block is False


def test_classify_includes_domain_age_in_evidence_and_prompt():
    client = _make_client('{"category": "SAFE", "confidence": 0.9, "reason": "ok"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    clf.classify("fresh-site.xyz", domain_age_days=7)
    prompt_sent = client.generate.call_args[0][0]
    assert '"domain_age_days": 7' in prompt_sent
    assert "domain_age_days" in classifier.CLASSIFICATION_PROMPT
