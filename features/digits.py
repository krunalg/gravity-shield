import re


def analyze(domain: str) -> dict:
    domain = domain.rstrip(".").lower()
    digits = re.findall(r"\d", domain)
    return {
        "digit_count": len(digits),
        "digit_ratio": len(digits) / len(domain) if domain else 0.0,
        "consecutive_digits": max((len(m.group(0)) for m in re.finditer(r"\d+", domain)), default=0),
        "leading_digits": bool(domain and domain[0].isdigit()),
        "trailing_digits": bool(domain and domain.split(".")[0][-1:].isdigit()),
    }
