from config import *
try:
    from config_local import *
except ImportError:
    pass


def score(lexical: dict, entropy: dict) -> float:
    score_value = 0.0
    if entropy["shannon"] >= ENTROPY_THRESHOLD:
        score_value += 0.35
    if lexical["vowel_ratio"] < 0.25 and lexical["hostname_length"] >= 10:
        score_value += 0.20
    if lexical["digit_ratio"] > 0.25:
        score_value += 0.15
    if lexical["dictionary_word_count"] == 0 and lexical["hostname_length"] >= 12:
        score_value += 0.20
    if lexical["repeated_characters"] or lexical["repeated_sequences"]:
        score_value += 0.10
    return min(score_value, 1.0)
