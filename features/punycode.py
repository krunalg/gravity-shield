def analyze(domain: str) -> dict:
    labels = domain.rstrip(".").lower().split(".")
    is_punycode = any(label.startswith("xn--") for label in labels)
    unicode_domain = domain
    homograph_score = 0.0
    if is_punycode:
        try:
            unicode_domain = domain.encode("ascii").decode("idna")
            homograph_score = 0.75
        except UnicodeError:
            homograph_score = 0.5
    return {
        "is_punycode": is_punycode,
        "unicode_domain": unicode_domain,
        "homograph_score": homograph_score,
    }
