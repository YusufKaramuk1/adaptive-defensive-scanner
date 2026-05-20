#!/usr/bin/env python3
"""
ADS – Ana Giriş Noktası
Adaptive Defensive Scanner v2.4

Kullanım:
  python main.py --target 192.168.1.1 --environment external --criticality high
  python main.py --target 192.168.1.0/24 --environment internal --criticality medium --parallel
  python main.py --target 10.0.0.1 --environment production --criticality high --mock
  python main.py --target 10.0.0.1 --environment external --criticality high --diff reports/eski.json
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import ScanContext, ScanReport, Environment, Criticality, RiskLevel, PriorityLevel
from scanner.nmap_scanner import run_scan
from scanner.subnet_scanner import run_parallel_scan
from analyzer.risk_mapper import analyze
from recommender.fix_generator import generate_fixes
from recommender.priority_engine import calculate_priority
from rule_generator.firewall_rules import generate_firewall_rules
from reporter.html_reporter import generate_html_report
from reporter.json_reporter import generate_json_report
from analyzer.scan_diff import compare_scans
from reporter.diff_reporter import generate_diff_html
from utils.helpers import is_valid_subnet


BANNER = """
╔══════════════════════════════════════════════════════╗
║       Adaptive Defensive Scanner  v2.4               ║
║       "Teknik bulguları güvenlik kararlarına"        ║
╚══════════════════════════════════════════════════════╝
"""

RISK_COLORS = {
    "high":   "\033[91m",
    "medium": "\033[93m",
    "low":    "\033[92m",
}
PRIORITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[96m",
    "LOW":      "\033[92m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"


def _color(text: str, level: str) -> str:
    return f"{RISK_COLORS.get(level, '')}{text}{RESET}"

def _priority_color(text: str, priority: str) -> str:
    return f"{PRIORITY_COLORS.get(priority, '')}{text}{RESET}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Adaptive Defensive Scanner (ADS) v2.4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python main.py --target 192.168.1.1 --environment external --criticality high
  python main.py --target 192.168.1.0/24 --environment internal --criticality medium --parallel
  python main.py --target localhost --environment production --criticality high --mock
  python main.py --target 10.0.0.1 --environment external --criticality high --diff reports/eski.json
        """,
    )
    parser.add_argument("--target",      required=True, help="Hedef IP, hostname veya subnet (CIDR)")
    parser.add_argument("--environment", required=True, choices=[e.value for e in Environment], help="Ortam bağlamı")
    parser.add_argument("--criticality", required=True, choices=[c.value for c in Criticality], help="Varlık kritikliği")
    parser.add_argument("--mock",   action="store_true", help="Gerçek Nmap yerine örnek veri kullan")
    parser.add_argument("--json",   action="store_true", help="JSON raporu oluştur")
    parser.add_argument("--no-html", action="store_true", help="HTML raporu oluşturma")
    parser.add_argument("--diff",   type=str, default=None, help="Karşılaştırma için önceki JSON rapor dosyası")
    parser.add_argument("--parallel", action="store_true", help="Subnet taramayı paralel yap")
    parser.add_argument("--workers", type=int, default=10, help="Paralel tarama işçi sayısı (varsayılan: 10)")
    return parser.parse_args()


def print_summary(report: ScanReport) -> None:
    print(f"\n{BOLD}{'─'*68}{RESET}")
    print(f"{BOLD}{'TARAMA SONUÇLARI':^68}{RESET}")
    print(f"{BOLD}{'─'*68}{RESET}")
    for item in report.findings:
        risk_val  = item.risk.value
        conf_val  = item.confidence.value.upper()
        prio_val  = item.priority.value.upper()
        cve_str = ""
        if item.cves:
            ids = ", ".join(c["cve_id"] if isinstance(c, dict) else c.cve_id for c in item.cves[:2])
            cve_str = f" {DIM}[{ids}]{RESET}"
        conf_color = {"HIGH": "\033[92m", "MEDIUM": "\033[93m", "LOW": "\033[91m"}.get(conf_val, "")
        conf_str = f"{conf_color}[Güven: {conf_val}]{RESET}"
        prio_str = _priority_color(f"[{prio_val}]", prio_val)
        evidence_str = ""
        if item.evidence:
            evidence_str = f" {DIM}({'; '.join(item.evidence[:2])}){RESET}"

        host_str = f"{item.host:<15}" if getattr(item, "host", "") else " " * 15

        print(
            f"  {CYAN}{host_str}{RESET} "
            f"Port {item.port:>5} "
            f"({item.service:<16}) → "
            f"Risk: {_color(risk_val.upper(), risk_val):<20} "
            f"Skor: {item.final_score}/5 {conf_str} {prio_str}{cve_str}"
            f"{evidence_str}"
        )
    ctx = report.context
    env_val  = ctx.environment.value if hasattr(ctx.environment, "value") else str(ctx.environment)
    crit_val = ctx.criticality.value if hasattr(ctx.criticality, "value") else str(ctx.criticality)
    print(f"\n{BOLD}{'─'*68}{RESET}")
    print(f"  Hedef             : {CYAN}{ctx.target}{RESET}")
    print(f"  Ortam             : {env_val.upper()}")
    print(f"  Kritiklik         : {crit_val.upper()}")
    print(f"  Toplam            : {len(report.findings)} bulgu  "
          f"| {_color(str(report.high_count)+' yüksek', 'high')}  "
          f"| {_color(str(report.medium_count)+' orta', 'medium')}  "
          f"| {_color(str(report.low_count)+' düşük', 'low')}")
    print(f"  Kritik öncelikli  : {_priority_color(str(report.critical_priority_count), 'CRITICAL')}")
    print(f"  Yüksek öncelikli  : {_priority_color(str(report.high_priority_count), 'HIGH')}")
    overall_risk = report.overall_risk
    overall_prio = report.overall_priority
    print(f"  Genel Risk        : {_color(overall_risk, overall_risk.lower())}")
    print(f"  Genel Öncelik     : {_priority_color(overall_prio, overall_prio)}")
    print(f"{BOLD}{'─'*68}{RESET}\n")


def main() -> None:
    print(BANNER)
    args = parse_args()

    ctx = ScanContext(
        target      = args.target,
        environment = Environment(args.environment),
        criticality = Criticality(args.criticality),
    )

    print(f"[ADS] Hedef     : {args.target}")
    print(f"[ADS] Ortam     : {args.environment}")
    print(f"[ADS] Kritiklik : {args.criticality}")
    print(f"[ADS] Mock mod  : {'AÇIK' if args.mock else 'KAPALI'}")
    if args.parallel:
        print(f"[ADS] Paralel   : AÇIK (workers: {args.workers})")
    if args.diff:
        print(f"[ADS] Diff      : {args.diff}")
    print()

    # 1. Tarama
    target = args.target
    is_subnet = is_valid_subnet(target)

    if is_subnet and args.parallel:
        raw_findings = run_parallel_scan(subnet=target, max_workers=args.workers, mock=args.mock)
    elif is_subnet and not args.parallel:
        print("[ADS] Uyarı: Subnet tespit edildi ama --parallel verilmedi. "
              "Tek IP gibi taranacak (Nmap normal mod). Bu uzun sürebilir.")
        raw_findings = run_scan(target, mock=args.mock)
    else:
        raw_findings = run_scan(target, mock=args.mock)

    if not raw_findings:
        print("[ADS] Açık port bulunamadı. Tarama sona erdi.")
        return

    # 2. Analiz
    analyzed = analyze(findings=raw_findings, environment=args.environment, criticality=args.criticality)

    # 3. Fix + Firewall + Priority
    for item in analyzed:
        fixes = generate_fixes(item)
        rules = generate_firewall_rules(item, args.environment)
        item.quick_fix     = fixes.quick_fix
        item.proper_fix    = fixes.proper_fix
        item.ufw_rule      = rules.ufw
        item.iptables_rule = rules.iptables
        item.rule_note     = rules.note
        item.priority = calculate_priority(item, args.environment, args.criticality)

    report = ScanReport(context=ctx, findings=analyzed)
    print_summary(report)

    # 4. JSON (her zaman üret)
    json_path = generate_json_report(report)
    if args.json:
        print(f"[ADS] JSON raporu : {json_path}")

    # 5. HTML
    if not args.no_html:
        html_path = generate_html_report(report)
        print(f"[ADS] HTML raporu : {html_path}")

    # 6. Diff
    if args.diff:
        try:
            diff_report = compare_scans(args.diff, json_path)
            diff_html_path = generate_diff_html(diff_report)
            print(f"[ADS] Diff raporu: {diff_html_path}")
        except FileNotFoundError as e:
            print(f"[ADS] Diff hatası: {e}")

    print("\n[ADS] Tarama tamamlandı.")


if __name__ == "__main__":
    main()