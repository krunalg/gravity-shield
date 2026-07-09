import math


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalized_entropy(text: str) -> float:
    if len(text) <= 1:
        return 0.0
    max_entropy = math.log2(len(set(text)))
    if max_entropy == 0:
        return 0.0
    return min(shannon_entropy(text) / max_entropy, 1.0)
