import re

import tldextract

# suffix_list_urls=() disables runtime PSL fetching — uses the snapshot
# bundled with the tldextract package, keeping the daemon fully offline.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())
# Private-domain-aware extraction: on shared-hosting platforms (github.io,
# pages.dev, ... — the PSL private section) the user-controlled label is the
# hostname that lexical/brand analysis must inspect.
_tld_extract_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_VOWELS = set("aeiou")
_WORD_HINTS = {
    "login", "secure", "account", "bank", "pay", "cdn", "mail", "api",
    "auth", "cloud", "static", "support", "admin", "service", "update",
}


def registered_domain(domain: str) -> str:
    domain = domain.rstrip(".").lower()
    ext = _tld_extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    # No recognized public suffix (e.g. single label, .local) — fall back
    labels = domain.split(".")
    if len(labels) < 2:
        return domain
    return ".".join(labels[-2:])


def registered_domain_private(domain: str) -> str:
    """Registered domain honouring PSL private suffixes: on shared hosting the
    user-owned unit is e.g. evil.github.io, not github.io."""
    domain = domain.rstrip(".").lower()
    ext = _tld_extract_private(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return registered_domain(domain)


def icann_hostname(domain: str) -> str:
    """Registrable label under ICANN suffixes only (ignores PSL private domains)."""
    domain = domain.rstrip(".").lower()
    ext = _tld_extract(domain)
    if ext.domain:
        return ext.domain
    return registered_domain(domain).split(".")[0]


def hostname(domain: str) -> str:
    domain = domain.rstrip(".").lower()
    ext = _tld_extract_private(domain)
    if ext.domain:
        return ext.domain
    return registered_domain(domain).split(".")[0]


def analyze(domain: str) -> dict:
    domain = domain.rstrip(".").lower()
    labels = [label for label in domain.split(".") if label]
    host = hostname(domain)
    label_lengths = [len(label) for label in labels] or [0]
    alpha = [char for char in domain if char.isalpha()]
    vowels = sum(1 for char in alpha if char in _VOWELS)
    consonants = len(alpha) - vowels
    digits = sum(1 for char in domain if char.isdigit())
    specials = sum(1 for char in domain if not char.isalnum() and char != ".")
    repeated_chars = len(re.findall(r"(.)\1{2,}", domain))
    repeated_sequences = len(re.findall(r"([a-z0-9]{2,})\1", domain))
    dictionary_words = sum(1 for word in _WORD_HINTS if word in domain)

    return {
        "length": len(domain),
        "hostname_length": len(host),
        "registered_domain_length": len(registered_domain(domain)),
        "label_count": len(labels),
        "subdomain_count": max(len(labels) - 2, 0),
        "average_label_length": sum(label_lengths) / len(label_lengths),
        "longest_label": max(label_lengths),
        "shortest_label": min(label_lengths),
        "vowel_count": vowels,
        "consonant_count": consonants,
        "vowel_ratio": vowels / len(alpha) if alpha else 0.0,
        "consonant_ratio": consonants / len(alpha) if alpha else 0.0,
        "digit_ratio": digits / len(domain) if domain else 0.0,
        "special_character_ratio": specials / len(domain) if domain else 0.0,
        "repeated_characters": repeated_chars,
        "repeated_sequences": repeated_sequences,
        "dictionary_word_count": dictionary_words,
    }
