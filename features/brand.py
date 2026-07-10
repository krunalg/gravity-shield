from config import *
try:
    from config_local import *
except ImportError:
    pass

from .lexical import hostname

_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def detect(domain: str) -> dict:
    raw_host = hostname(domain)
    candidates = {raw_host.replace("-", ""), raw_host.translate(_LEET_TRANSLATION).replace("-", "")}
    candidates.update(part for part in raw_host.split("-") if part)
    candidates.update(part.translate(_LEET_TRANSLATION) for part in raw_host.split("-") if part)
    best = {"matched_brand": None, "confidence": 0.0, "edit_distance": None, "match_type": None}
    for brand in KNOWN_BRANDS:
        for candidate in candidates:
            distance = _levenshtein(candidate, brand)
            confidence = 1.0 - (distance / max(len(candidate), len(brand), 1))
            contains = brand in candidate and candidate != brand
            if contains:
                confidence = max(confidence, 0.85)
            if confidence > best["confidence"]:
                if distance == 0:
                    mtype = "exact"
                elif contains:
                    mtype = "contains"
                else:
                    mtype = "fuzzy"
                best = {
                    "matched_brand": brand.title(),
                    "confidence": confidence,
                    "edit_distance": distance,
                    "match_type": mtype,
                }
    if best["confidence"] < BRAND_MATCH_THRESHOLD:
        best["matched_brand"] = None
    return best
