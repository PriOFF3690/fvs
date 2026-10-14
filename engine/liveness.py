"""
Stage 3: Liveness / reachability check.

Responsibility of this module ONLY:
    - Given a validated target (from validate.classify_input), check if it responds to ICMP ping
    - For "url" type, extract the host first, then ping that host
    - Return structured data: is it live, and basic ping stats

Does NOT do DNS recon, port scanning, or web fingerprinting - that's later stages.
"""

from urllib.parse import urlparse
from icmplib import ping as icmp_ping, NameLookupError, ICMPSocketError


def check_live(target: dict) -> dict:
    """
    Check reachability of a classified target via ICMP ping.

    `target` is the dict returned by validate.classify_input(), e.g.
        {"type": "domain", "value": "example.com", "valid": True}

    Returns:
        {
            "live": True/False,
            "host": "example.com",          # the actual host that was pinged
            "rtt_avg_ms": 12.4,             # None if not live
            "packet_loss_pct": 0.0,         # None if ping couldn't run at all
            "error": None or "reason"
        }
    """
    if not target.get("valid"):
        return _dead(target.get("value"), "Target failed validation, cannot check liveness")

    host = _extract_host(target)

    try:
        result = icmp_ping(host, count=3, timeout=2, privileged=False)
    except NameLookupError:
        return _dead(host, "Could not resolve hostname")
    except ICMPSocketError as e:
        return _dead(host, f"ICMP socket error (permissions?): {e}")
    except Exception as e:
        return _dead(host, f"Unexpected ping failure: {e}")

    if result.is_alive:
        return {
            "live": True,
            "host": host,
            "rtt_avg_ms": round(result.avg_rtt, 2),
            "packet_loss_pct": round(result.packet_loss * 100, 1),
            "error": None,
        }
    else:
        return _dead(host, "No ping response (host may be down or blocking ICMP)")


def _extract_host(target: dict) -> str:
    """Pull a bare host out of ip/domain/url types."""
    if target["type"] == "url":
        return urlparse(target["value"]).hostname
    return target["value"]


def _dead(host, reason: str) -> dict:
    return {
        "live": False,
        "host": host,
        "rtt_avg_ms": None,
        "packet_loss_pct": None,
        "error": reason,
    }