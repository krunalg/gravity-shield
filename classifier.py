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

from ollama_client import OllamaClient

logger = logging.getLogger(__name__)

_JSON_RE = re.compile(r'\{[^{}]+\}', re.DOTALL)

CLASSIFICATION_PROMPT = """You are a DNS security analyst. Classify the following domain name.

Domain: {domain}

Classify it as exactly one of these categories:
- MALWARE: domain used to distribute malware or as C2 (command and control)
- PHISHING: domain impersonating legitimate services to steal credentials
- C2: command and control server for botnets or RATs
- RANSOMWARE: associated with ransomware operations
- AD: advertising domain
- TRACKER: analytics or user tracking domain
- SAFE: legitimate domain, not malicious

Consider:
- Random-looking subdomains (DGA patterns) suggest MALWARE or C2
- Typosquatting of known brands (g00gle, paypa1, hdfc-secure) suggests PHISHING
- Unusual TLDs (.ru, .xyz, .tk, .pw, .cc) combined with suspicious names raise risk
- Legitimate CDNs, software companies, government are SAFE

Respond with valid JSON only, no extra text:
{{"category": "CATEGORY", "confidence": 0.00, "reason": "one sentence explanation"}}"""


@dataclass
class ClassificationResult:
    domain: str
    category: str
    confidence: float
    reason: str
    should_block: bool
    raw_response: Optional[str] = None

    @classmethod
    def unknown(cls, domain: str, raw: Optional[str] = None) -> "ClassificationResult":
        return cls(
            domain=domain,
            category="UNKNOWN",
            confidence=0.0,
            reason="Could not parse model response",
            should_block=False,
            raw_response=raw,
        )


class DomainClassifier:
    def __init__(self, ollama_client: Optional[OllamaClient] = None):
        self._client = ollama_client or OllamaClient()

    def classify(self, domain: str) -> ClassificationResult:
        prompt = CLASSIFICATION_PROMPT.format(domain=domain)
        raw = self._client.generate(prompt)

        if not raw:
            return ClassificationResult.unknown(domain, raw)

        parsed = self._parse_response(raw)
        if not parsed:
            logger.debug(f"Could not parse response for {domain}: {raw[:100]}")
            return ClassificationResult.unknown(domain, raw)

        category = parsed.get("category", "UNKNOWN").upper()
        confidence = float(parsed.get("confidence", 0.0))
        reason = parsed.get("reason", "")

        should_block = (
            category in CATEGORIES_TO_BLOCK
            and confidence >= BLOCK_CONFIDENCE_THRESHOLD
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
