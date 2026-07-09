from config import *
try:
    from config_local import *
except ImportError:
    pass


def is_never_block_domain(domain: str) -> bool:
    domain = domain.rstrip(".").lower()
    return domain in NEVER_BLOCK_DOMAINS or domain.endswith(tuple(NEVER_BLOCK_SUFFIXES))


def should_skip_classification(domain: str) -> bool:
    return is_never_block_domain(domain)
