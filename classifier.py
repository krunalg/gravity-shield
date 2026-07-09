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

CLASSIFICATION_PROMPT = """You are a DNS security analyst. Classify this domain using only the structured evidence provided.

Classify it as exactly one of these categories:
- MALWARE: domain used to distribute malware or as C2 (command and control)
- PHISHING: domain impersonating legitimate services to steal credentials
- C2: command and control server for botnets or RATs
- RANSOMWARE: associated with ransomware operations
- AD: advertising domain
- TRACKER: analytics or user tracking domain
- SAFE: legitimate domain, not malicious

Do not calculate entropy, edit distance, DGA likelihood, TLD reputation, or brand similarity yourself.
Use the supplied evidence to correlate risk and explain the verdict.

Respond with valid JSON only, no extra text:
{{
  "classification": "CATEGORY",
  "confidence": 0.00,
  "severity": "INFO|LOW|MEDIUM|HIGH",
  "risk_score": 0,
  "reasons": ["short evidence-based reason"],
  "recommended_action": "ALLOW|BLOCK"
}}

Evidence:
{evidence_json}"""


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
        prompt = CLASSIFICATION_PROMPT.format(evidence_json=json.dumps(features, sort_keys=True))
        raw = self._client.generate(prompt)

        if not raw:
            result = ClassificationResult.unknown(domain, raw)
            result.features = features
            return result

        parsed = self._parse_response(raw)
        if not parsed:
            logger.debug(f"Could not parse response for {domain}: {raw[:100]}")
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

        logger.info(
            f"Classified {domain}: {category} ({confidence:.0%}) "
            f"{'→ BLOCK' if should_block else '→ allow'} | {reason}"
        )

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
