import argparse

from scanner.nmap_scanner import run_scan
from analyzer.risk_mapper import analyze
from recommender.fix_generator import generate_fixes


def parse_args():
    parser = argparse.ArgumentParser(
        description="Adaptive Defensive Scanner (ADS)"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "--environment",
        required=True,
        choices=["internal", "external", "production"],
        help="Environment context"
    )

    parser.add_argument(
        "--criticality",
        required=True,
        choices=["low", "medium", "high"],
        help="Asset criticality"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    print("=== ADS START ===")
    print(f"Target: {args.target}")
    print(f"Environment: {args.environment}")
    print(f"Criticality: {args.criticality}")

    findings = run_scan(args.target)

    analyzed = analyze(
        findings=findings,
        environment=args.environment,
        criticality=args.criticality
    )

    print("\n=== RESULTS ===")

    if not analyzed:
        print("No open ports found.")
        return

    for item in analyzed:
        fixes = generate_fixes(item)

        print(f"Port {item['port']} ({item['service']}) → Risk: {item['risk']}")
        print(f"Score: {item['final_score']}/5")
        print(f"Reason: {item['reason']}")
        print(f"Quick Fix: {fixes['quick_fix']}")
        print(f"Proper Fix: {fixes['proper_fix']}")
        print()


if __name__ == "__main__":
    main()