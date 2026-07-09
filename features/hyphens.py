def analyze(domain: str) -> dict:
    host = domain.rstrip(".").lower().split(".")[0]
    return {
        "hyphen_count": domain.count("-"),
        "starts_with_hyphen": host.startswith("-"),
        "ends_with_hyphen": host.endswith("-"),
        "consecutive_hyphens": "--" in domain,
    }
