"""Bounded byte deletion preserving an exact mismatch predicate."""

from collections.abc import Callable
from hashlib import sha256


def ddmin(original: bytes, preserves: Callable[[bytes], bool], budget: int = 250) -> tuple[bytes, dict]:
    """Try chunk deletions, caching each tested input by SHA-256."""
    current, granularity = original, 2
    cache = {sha256(original).hexdigest(): True}
    attempts, hits = 0, 0
    while current:
        size = (len(current) + granularity - 1) // granularity
        for start in range(0, len(current), size):
            candidate = current[:start] + current[start + size:]
            digest = sha256(candidate).hexdigest()
            if digest in cache:
                hits += 1
            elif attempts >= budget:
                return current, dict(status="budget_exhausted", attempts=attempts, budget=budget, cache_hits=hits)
            else:
                cache[digest] = preserves(candidate)
                attempts += 1
            if cache[digest]:
                current = candidate
                granularity = max(2, granularity - 1)
                break
        else:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current, dict(status="reduced" if current != original else "no_reduction",
                         attempts=attempts, budget=budget, cache_hits=hits)
