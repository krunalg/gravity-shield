from config import *
try:
    from config_local import *
except ImportError:
    pass


def analyze(domain: str) -> dict:
    labels = domain.rstrip(".").lower().split(".")
    tld = f".{labels[-1]}" if labels and labels[-1] else ""
    suspicious = tld in HIGH_RISK_TLDS
    return {
        "tld": tld.lstrip("."),
        "tld_risk": 0.8 if suspicious else 0.1,
        "suspicious_tld": suspicious,
        "uncommon_tld": suspicious,
    }
