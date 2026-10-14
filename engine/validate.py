"""
Stage 1 + 2: Input intake and format validation.

Responsibility of this module ONLY:
    - Take raw user input (string)
    - Figure out if it's an ip / domain / url
    - Validate its format
    - Return a clean, structured result

It does NOT check if the target is reachable (that's liveness.py, next stage).
It does NOT print anything. Pure function in, structured data out.
"""

import validators
from urllib.parse import urlparse


def classify_input(raw: str) -> dict:
    """
    Classify and validate a raw target string.

    Returns a dict like:
        {"type": "ip",     "value": "1.2.3.4",            "valid": True}
        {"type": "domain", "value": "example.com",        "valid": True}
        {"type": "url",    "value": "https://example.com","valid": True}
        {"type": "invalid","value": "<raw input>",        "valid": False, "error": "..."}
    """
    if raw is None:
        return _invalid(raw, "No input provided")

    target = raw.strip()

    if not target:
        return _invalid(raw, "Empty input")

    # --- Check URL first (most specific: has a scheme) ---
    if "://" in target:
        if validators.url(target):
            parsed = urlparse(target)
            if parsed.scheme not in ("http", "https"):
                return _invalid(target, f"Unsupported URL scheme: {parsed.scheme}")
            return {"type": "url", "value": target, "valid": True}
        else:
            return _invalid(target, "Looks like a URL but format is invalid")

    # --- Check IPv4 ---
    if validators.ipv4(target):
        return {"type": "ip", "value": target, "valid": True}

    # --- Check IPv6 (good to support early, cheap to add) ---
    if validators.ipv6(target):
        return {"type": "ip", "value": target, "valid": True}

    # --- Check domain ---
    if validators.domain(target):
        return {"type": "domain", "value": target, "valid": True}

    return _invalid(target, "Input is not a valid IP, domain, or URL")


def _invalid(raw, reason: str) -> dict:
    return {"type": "invalid", "value": raw, "valid": False, "error": reason}