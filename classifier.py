from config import *
try:
    from config_local import *
except ImportError:
    pass

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

from features.extractor import extract
from ollama_client import OllamaClient

logger = logging.getLogger(__name__)

_JSON_RE = re.compile(r'\{[^{}]+\}', re.DOTALL)

CLASSIFICATION_PROMPT = """You are a DNS security analyst. Classify the domain below using ONLY the pre-computed evidence provided. Do not recalculate any values yourself.

Categories (pick exactly one):
MALWARE | PHISHING | C2 | RANSOMWARE | AD | TRACKER | SAFE

Rules:
- risk_score must reflect the evidence: rule_score={rule_score}, adjust up/down based on your reasoning
- If threat_intel shows a feed hit, trust it — score high
- Brand impersonation + suspicious TLD = strong phishing signal
- High DGA score + high entropy = likely C2/malware
- Set recommended_action=BLOCK only for MALWARE, PHISHING, C2, RANSOMWARE

Respond with JSON only — no markdown, no explanation outside the JSON:
{{
  "classification": "CATEGORY",
  "confidence": 0.00,
  "severity": "INFO|LOW|MEDIUM|HIGH",
  "risk_score": 0,
  "reasons": ["concise evidence-based reason"],
  "recommended_action": "ALLOW|BLOCK"
}}

Evidence:
{evidence_json}"""


def _build_evidence(features: dict) -> dict:
    """Distil full feature dict into a concise evidence summary for the LLM."""
    rules = features.get("rules", {})
    brand = features.get("brand", {})
    entropy = features.get("entropy", {})
    tld = features.get("tld", {})
    threat = features.get("threat_context", {})
    lexical = features.get("lexical", {})
    return {
        "domain": features.get("domain", ""),
        "rule_score": rules.get("rule_score", 0),
        "severity": rules.get("severity", "INFO"),
        "rule_reasons": rules.get("rule_reasons", []),
        "entropy_shannon": round(entropy.get("shannon", 0), 2),
        "dga_score": round(features.get("dga_score", 0), 2),
        "tld": tld.get("tld", ""),
        "suspicious_tld": tld.get("suspicious_tld", False),
        "label_count": lexical.get("label_count", 0),
        "length": lexical.get("length", 0),
        "digit_ratio": round(lexical.get("digit_ratio", 0), 2),
        "brand_match": brand.get("matched_brand"),
        "brand_confidence": round(brand.get("confidence", 0), 2),
        "is_punycode": features.get("punycode", {}).get("is_punycode", False),
        "threat_intel": {
            "urlhaus_hit": threat.get("urlhaus_hit", False),
            "feed_source": threat.get("feed_source"),
            "ioc_category": threat.get("ioc_category"),
        } if threat else {},
    }


@dataclass
class ClassificationResult:
    domain: str
    category: str
    confidence: float
    reason: str
    should_block: bool
    raw_response: Optional[str] = None
    severity: str = "INFO"
    risk_score: int = 0
    reasons: Optional[list[str]] = None
    features: Optional[dict] = None

    @classmethod
    def unknown(cls, domain: str, raw: Optional[str] = None) -> "ClassificationResult":
        return cls(
            domain=domain,
            category="UNKNOWN",
            confidence=0.0,
            reason="Could not parse model response",
            should_block=False,
            raw_response=raw,
            reasons=[],
        )


class DomainClassifier:
    def __init__(self, ollama_client: Optional[OllamaClient] = None):
        self._client = ollama_client or OllamaClient()

    def classify(self, domain: str, threat_context: Optional[dict] = None) -> ClassificationResult:
        features = extract(domain, threat_context=threat_context)
        evidence = _build_evidence(features)
        rule_score = evidence["rule_score"]
        prompt = CLASSIFICATION_PROMPT.format(
            rule_score=rule_score,
            evidence_json=json.dumps(evidence, indent=2),
        )
        logger.debug(f"Ollama evidence for {domain}: {json.dumps(evidence)}")
        raw = self._client.generate(prompt)
        logger.debug(f"Ollama raw response for {domain}: {raw!r}")

        if not raw:
            result = ClassificationResult.unknown(domain, raw)
            result.features = features
            return result

        parsed = self._parse_response(raw)
        if not parsed:
            logger.warning(f"Unparseable Ollama response for {domain}: {raw[:200]!r}")
            result = ClassificationResult.unknown(domain, raw)
            result.features = features
            return result

        category = parsed.get("classification", parsed.get("category", "UNKNOWN")).upper()
        confidence = float(parsed.get("confidence", 0.0))
        reasons = parsed.get("reasons", [])
        if isinstance(reasons, str):
            reasons = [reasons]
        reason = parsed.get("reason", "; ".join(reasons))
        severity = parsed.get("severity", features["rules"]["severity"]).upper()
        risk_score = int(parsed.get("risk_score", features["rules"]["rule_score"]))
        recommended_action = parsed.get("recommended_action", "").upper()

        if recommended_action:
            action_blocks = recommended_action == "BLOCK"
        else:
            action_blocks = category in CATEGORIES_TO_BLOCK

        should_block = (
            action_blocks
            and category in CATEGORIES_TO_BLOCK
            and confidence >= BLOCK_CONFIDENCE_THRESHOLD
            and risk_score >= RULE_SCORE_THRESHOLD
        )

        if should_block:
            logger.info(f"Classified {domain}: {category} ({confidence:.0%}) risk={risk_score} → BLOCK | {reason}")
        elif category in CATEGORIES_TO_BLOCK:
            # Explain why a potentially risky domain was allowed
            gates = []
            if not action_blocks:
                gates.append(f"action={recommended_action or 'none'}")
            if confidence < BLOCK_CONFIDENCE_THRESHOLD:
                gates.append(f"confidence={confidence:.0%}<{BLOCK_CONFIDENCE_THRESHOLD:.0%}")
            if risk_score < RULE_SCORE_THRESHOLD:
                gates.append(f"risk_score={risk_score}<{RULE_SCORE_THRESHOLD}")
            logger.info(f"Classified {domain}: {category} ({confidence:.0%}) risk={risk_score} → allow [{', '.join(gates)}] | {reason}")
        else:
            logger.info(f"Classified {domain}: {category} ({confidence:.0%}) → allow | {reason}")

        return ClassificationResult(
            domain=domain,
            category=category,
            confidence=confidence,
            reason=reason,
            should_block=should_block,
            raw_response=raw,
            severity=severity,
            risk_score=risk_score,
            reasons=reasons,
            features=features,
        )

    def _parse_response(self, text: str) -> Optional[dict]:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
        match = _JSON_RE.search(text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None
