"""
CLI entrypoint - currently wires up ONLY Stage 1 (input) + Stage 2 (validation) + Stage 3 (liveness).
Next stages (DNS/WHOIS/port recon, web fingerprinting, etc.) will plug in after this is confirmed solid.
"""

import argparse
import json
from engine import validate, liveness


def main():
    parser = argparse.ArgumentParser(description="Recon & Vulnerability Scanner (dev build)")
    parser.add_argument("target", help="IP address, domain, or URL to scan")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")
    args = parser.parse_args()

    # Stage 2: validation
    val_result = validate.classify_input(args.target)

    if not val_result["valid"]:
        if args.json:
            print(json.dumps({"validation": val_result}, indent=2))
        else:
            print(f"[FAIL] {val_result['error']}")
            print(f"       Input: {val_result['value']}")
        return

    # Stage 3: liveness (only runs if validation passed)
    live_result = liveness.check_live(val_result)

    if args.json:
        print(json.dumps({"validation": val_result, "liveness": live_result}, indent=2))
        return

    print(f"[OK] Input accepted")
    print(f"     Type : {val_result['type']}")
    print(f"     Value: {val_result['value']}")
    print()
    if live_result["live"]:
        print(f"[OK] Target is live")
        print(f"     Host           : {live_result['host']}")
        print(f"     Avg RTT        : {live_result['rtt_avg_ms']} ms")
        print(f"     Packet loss    : {live_result['packet_loss_pct']}%")
    else:
        print(f"[FAIL] Target is unreachable")
        print(f"       Host  : {live_result['host']}")
        print(f"       Reason: {live_result['error']}")


if __name__ == "__main__":
    main()