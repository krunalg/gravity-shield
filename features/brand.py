from config import *
try:
    from config_local import *
except ImportError:
    pass

from .lexical import hostname, registered_domain

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


_NO_MATCH = {"matched_brand": None, "confidence": 0.0, "edit_distance": None, "match_type": None}


def _candidates(raw_host: str) -> list[tuple[str, bool, bool]]:
    """Return (candidate, via_leet, via_part) tuples derived from the hostname."""
    out = []
    base = raw_host.replace("-", "")
    out.append((base, False, False))
    leet_base = base.translate(_LEET_TRANSLATION)
    if leet_base != base:
        out.append((leet_base, True, False))
    for part in raw_host.split("-"):
        if not part or part == base:
            continue
        out.append((part, False, True))
        leet_part = part.translate(_LEET_TRANSLATION)
        if leet_part != part:
            out.append((leet_part, True, True))
    return out


def detect(domain: str) -> dict:
    apex = registered_domain(domain)
    for brand, official_domain in KNOWN_BRANDS.items():
        if apex == official_domain:
            return {
                "matched_brand": brand.title(),
                "confidence": 1.0,
                "edit_distance": 0,
                "match_type": "official",
            }

    raw_host = hostname(domain)
    best = dict(_NO_MATCH)
    for brand in KNOWN_BRANDS:
        for candidate, via_leet, via_part in _candidates(raw_host):
            distance = _levenshtein(candidate, brand)
            confidence = 1.0 - (distance / max(len(candidate), len(brand), 1))
            contains = brand in candidate and candidate != brand
            if contains:
                confidence = max(confidence, 0.85)
            if confidence > best["confidence"]:
                if via_leet:
                    mtype = "leet"
                elif via_part:
                    mtype = "embedded"
                elif distance == 0:
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
        return dict(_NO_MATCH)
    return best
