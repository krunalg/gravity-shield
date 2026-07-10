from . import brand, dga, digits, entropy, hyphens, lexical, punycode, rules, tld


def extract(domain: str, threat_context: dict | None = None,
            brands: dict[str, str] | None = None) -> dict:
    normalized = domain.rstrip(".").lower()
    lexical_features = lexical.analyze(normalized)
    entropy_features = {
        "shannon": entropy.shannon_entropy(lexical.hostname(normalized)),
        "normalized": entropy.normalized_entropy(lexical.hostname(normalized)),
    }
    features = {
        "domain": normalized,
        "lexical": lexical_features,
        "entropy": entropy_features,
        "tld": tld.analyze(normalized),
        "digits": digits.analyze(normalized),
        "hyphens": hyphens.analyze(normalized),
        "punycode": punycode.analyze(normalized),
        "brand": brand.detect(normalized, brands=brands),
        "threat_context": threat_context or {},
    }
    features["dga_score"] = dga.score(lexical_features, entropy_features)
    features["rules"] = rules.evaluate(features)
    return features
