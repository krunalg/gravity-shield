import os, sys, json
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import classifier

def _make_client(response_text: str):
    mock = MagicMock()
    mock.generate.return_value = response_text
    return mock

def test_classify_malware_domain():
    client = _make_client('{"category": "MALWARE", "confidence": 0.95, "reason": "C2 beacon pattern"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("evil-c2-beacon.ru")
    assert result.category == "MALWARE"
    assert result.confidence == 0.95
    assert result.should_block is True

def test_classify_safe_domain():
    client = _make_client('{"category": "SAFE", "confidence": 0.99, "reason": "Legitimate CDN"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("cdn.example.com")
    assert result.category == "SAFE"
    assert result.should_block is False

def test_classify_low_confidence_not_blocked():
    client = _make_client('{"category": "MALWARE", "confidence": 0.60, "reason": "uncertain"}')
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
    client = _make_client('{"category": "PHISHING", "confidence": 0.88, "reason": "fake bank"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    result = clf.classify("secure-hdfc-login.xyz")
    assert result.should_block is True

def test_prompt_contains_domain():
    client = _make_client('{"category": "SAFE", "confidence": 0.9, "reason": "ok"}')
    clf = classifier.DomainClassifier(ollama_client=client)
    clf.classify("targetdomain.com")
    prompt_sent = client.generate.call_args[0][0]
    assert "targetdomain.com" in prompt_sent
