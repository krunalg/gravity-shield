from config import *
try:
    from config_local import *
except ImportError:
    pass

import json
import logging
from dataclasses import dataclass
from typing import Optional

from features.extractor import extract
from ollama_client import OllamaClient

logger = logging.getLogger(__name__)

CLASSIFICATION_PROMPT = """You are a DNS security analyst. Classify the domain below using ONLY the pre-computed evidence provided. Do not recalculate any values yourself.

Categories (pick exactly one):
MALWARE | PHISHING | C2 | RANSOMWARE | AD | TRACKER | SAFE

Rules:
- risk_score must reflect the evidence: rule_score={rule_score}, adjust up/down based on your reasoning
- If threat_intel shows a feed hit, trust it — score high
- brand_match_type="official": registered domain IS the brand's official domain — SAFE, never impersonation
- brand_match_type="exact": hostname equals the brand name but on a NON-official registered domain — suspicious, likely impersonation
- brand_match_type="leet": brand name spelled with character substitutions (0→o, 1→l) — STRONG impersonation signal
- brand_match_type="embedded": brand name is a hyphen-separated part of the hostname (e.g. paypal-login) — strong impersonation signal
- brand_match_type="contains": brand name is a substring of the registered domain — ambiguous: could be a brand-owned service domain or impersonation; this domain was NOT on the popularity allowlist, so weigh other signals (suspicious_tld, dga_score, entropy) before deciding
- brand_match_type="fuzzy": hostname merely resembles the brand — impersonation signal when combined with suspicious_tld or high dga_score
- domain_age_days: registration age via RDAP. Under 30 days = strong phishing/malware signal; under 180 = weak signal; null = unknown, ignore it
- shared_hosting_provider: hostname is user content on this platform (github.io, pages.dev, ...) — the subdomain owner is untrusted and the provider's reputation does NOT vouch for it; judge the subdomain label itself
- asn_flagged=true: domain resolves into a Spamhaus ASN-DROP network (hijacked or criminal-run) — very strong malicious-hosting signal
- tls_verify_failed=true: the host presented an invalid certificate (self-signed, expired, hostname mismatch) — suspicious for a domain pretending to be a service; tls_cert_age_days under 14 is a weak phishing signal (free CAs rotate certs often), null tls fields = unknown, ignore
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
        "brand_match_type": brand.get("match_type"),
        "is_punycode": features.get("punycode", {}).get("is_punycode", False),
        "domain_age_days": features.get("age", {}).get("age_days"),
        "shared_hosting_provider": features.get("shared_hosting", {}).get("provider"),
        "asn": features.get("asn", {}).get("asn"),
        "asn_flagged": features.get("asn", {}).get("flagged", False),
        "tls_issuer": (features.get("tls") or {}).get("issuer"),
        "tls_cert_age_days": (features.get("tls") or {}).get("cert_age_days"),
        "tls_verify_failed": (features.get("tls") or {}).get("verify_failed"),
        "tls_san_count": (features.get("tls") or {}).get("san_count"),
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

    def classify(self, domain: str, threat_context: Optional[dict] = None,
                 brands: Optional[dict] = None,
                 domain_age_days: Optional[int] = None,
                 shared_hosting_provider: Optional[str] = None,
                 asn_info: Optional[dict] = None,
                 tls_info: Optional[dict] = None) -> ClassificationResult:
        features = extract(domain, threat_context=threat_context, brands=brands,
                           domain_age_days=domain_age_days,
                           shared_hosting_provider=shared_hosting_provider,
                           asn_info=asn_info,
                           tls_info=tls_info)
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

        # Gate on the deterministic rule score, not the LLM-returned risk_score:
        # the model's arithmetic is advisory, the extractor's evidence is not.
        det_rule_score = features["rules"]["rule_score"]
        should_block = (
            action_blocks
            and category in CATEGORIES_TO_BLOCK
            and confidence >= BLOCK_CONFIDENCE_THRESHOLD
            and det_rule_score >= BLOCK_RULE_SCORE_FLOOR
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
            if det_rule_score < BLOCK_RULE_SCORE_FLOOR:
                gates.append(f"rule_score={det_rule_score}<{BLOCK_RULE_SCORE_FLOOR}")
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
        # Scan for the first parseable JSON object — raw_decode handles nested
        # braces that a flat regex cannot.
        decoder = json.JSONDecoder()
        idx = text.find("{")
        while idx != -1:
            try:
                obj, _ = decoder.raw_decode(text, idx)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass
            idx = text.find("{", idx + 1)
        return None
