import re

_VOWELS = set("aeiou")
_WORD_HINTS = {
    "login", "secure", "account", "bank", "pay", "cdn", "mail", "api",
    "auth", "cloud", "static", "support", "admin", "service", "update",
}


def registered_domain(domain: str) -> str:
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) < 2:
        return domain.lower()
    return ".".join(labels[-2:])


def hostname(domain: str) -> str:
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
