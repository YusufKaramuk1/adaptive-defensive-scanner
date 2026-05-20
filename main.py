#!/usr/bin/env python3
"""
ADS – Main Entry Point
Adaptive Defensive Scanner v1.0.0

Usage:
  python main.py --target 192.168.1.1 --environment external --criticality high
  python main.py --target 192.168.1.0/24 --environment internal --criticality medium --parallel
  python main.py --target 10.0.0.1 --environment external --criticality high --compare last
  python main.py --import-nmap-xml scans/nmap_result.xml --environment external --criticality high
  python main.py --import-httpx-jsonl test_data/httpx_import_test.jsonl --environment external --criticality medium
  python main.py --import-nuclei-json test_data/nuclei_import_test.jsonl --environment external --criticality high
  python main.py --history
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import ScanContext, ScanReport, Environment, Criticality
from scanner.nmap_scanner import run_scan
from scanner.subnet_scanner import run_parallel_scan
from integrations.nmap_xml_importer import import_nmap_xml, infer_target_label_from_findings
from integrations.osmedeus_httpx_importer import (
    import_httpx_jsonl,
    infer_target_label_from_httpx_findings,
)
from integrations.nuclei_json_importer import (
    import_nuclei_json,
    infer_target_label_from_nuclei_findings,
)
from analyzer.risk_mapper import analyze
from analyzer.security_finding_analyzer import analyze_security_findings
from recommender.fix_generator import generate_fixes
from recommender.priority_engine import calculate_priority
from rule_generator.firewall_rules import generate_firewall_rules
from reporter.html_reporter import generate_html_report
from reporter.json_reporter import generate_json_report
from reporter.security_json_reporter import generate_security_json_report
from analyzer.scan_diff import compare_scans
from reporter.diff_reporter import generate_diff_html
from utils.helpers import is_valid_subnet
from utils.storage import save_latest_scan, get_previous_scan_path, list_history


BANNER = """
╔══════════════════════════════════════════════════════╗
║       Adaptive Defensive Scanner  v1.0.0             ║
║       "From technical findings to security actions"  ║
╚══════════════════════════════════════════════════════╝
"""

RISK_COLORS = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}

PRIORITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[96m",
    "LOW": "\033[92m",
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"


def _color(text: str, level: str) -> str:
    return f"{RISK_COLORS.get(level, '')}{text}{RESET}"


def _priority_color(text: str, priority: str) -> str:
    return f"{PRIORITY_COLORS.get(priority, '')}{text}{RESET}"


def _normalize_display_path(path_value: str) -> str:
    return str(path_value).replace("\\", "/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Adaptive Defensive Scanner (ADS) v1.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 192.168.1.1 --environment external --criticality high
  python main.py --target 192.168.1.0/24 --environment internal --criticality medium --parallel
  python main.py --target 10.0.0.1 --environment external --criticality high --compare last
  python main.py --import-nmap-xml scans/nmap_result.xml --environment external --criticality high
  python main.py --import-httpx-jsonl test_data/httpx_import_test.jsonl --environment external --criticality medium
  python main.py --import-nuclei-json test_data/nuclei_import_test.jsonl --environment external --criticality high
  python main.py --history
        """,
    )

    parser.add_argument(
        "--target",
        default=None,
        help="Target IP, hostname, subnet, or custom import report label",
    )
    parser.add_argument(
        "--environment",
        default="internal",
        choices=[e.value for e in Environment],
        help="Environment context",
    )
    parser.add_argument(
        "--criticality",
        default="medium",
        choices=[c.value for c in Criticality],
        help="Asset criticality",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock data instead of running a real Nmap scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print generated JSON report path",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Do not generate HTML report",
    )
    parser.add_argument(
        "--diff",
        type=str,
        default=None,
        help="Previous JSON report file for comparison",
    )
    parser.add_argument(
        "--compare",
        type=str,
        default=None,
        help="Comparison mode: 'last' or a JSON report path",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run subnet scan in parallel",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of parallel scan workers",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show scan history",
    )
    parser.add_argument(
        "--import-nmap-xml",
        dest="import_nmap_xml",
        default=None,
        help="Import existing Nmap XML output into ADS pipeline",
    )
    parser.add_argument(
        "--import-httpx-jsonl",
        dest="import_httpx_jsonl",
        default=None,
        help="Import existing httpx / Osmedeus JSONL output into ADS pipeline",
    )
    parser.add_argument(
        "--import-nuclei-json",
        dest="import_nuclei_json",
        default=None,
        help="Import existing Nuclei JSON / JSONL output into ADS security pipeline",
    )

    return parser.parse_args()


def determine_scan_mode(args: argparse.Namespace, is_subnet: bool) -> str:
    if args.import_nmap_xml:
        return "nmap_xml_import"

    if args.import_httpx_jsonl:
        return "httpx_jsonl_import"

    if args.import_nuclei_json:
        return "nuclei_json_import"

    if args.mock:
        return "mock"

    if is_subnet and args.parallel:
        return "nmap_subnet_parallel"

    if is_subnet and not args.parallel:
        return "nmap_subnet_sequential"

    return "nmap_live"


def determine_source_info(args: argparse.Namespace) -> tuple[str, str]:
    if args.import_nmap_xml:
        return "nmap", _normalize_display_path(args.import_nmap_xml)

    if args.import_httpx_jsonl:
        return "httpx", _normalize_display_path(args.import_httpx_jsonl)

    if args.import_nuclei_json:
        return "nuclei", _normalize_display_path(args.import_nuclei_json)

    return "ads", ""


def validate_source_selection(args: argparse.Namespace) -> bool:
    import_sources = [
        bool(args.import_nmap_xml),
        bool(args.import_httpx_jsonl),
        bool(args.import_nuclei_json),
    ]

    if sum(import_sources) > 1:
        print("[ADS] Error: Only one import source can be used at a time.")
        print("[ADS] Use one of: --import-nmap-xml, --import-httpx-jsonl, --import-nuclei-json.")
        return False

    return True


def print_summary(report: ScanReport) -> None:
    print(f"\n{BOLD}{'─' * 68}{RESET}")
    print(f"{BOLD}{'SCAN RESULTS':^68}{RESET}")
    print(f"{BOLD}{'─' * 68}{RESET}")

    for item in report.findings:
        risk_val = item.risk.value
        conf_val = item.confidence.value.upper()
        prio_val = item.priority.value.upper()

        cve_str = ""

        if item.cves:
            ids = ", ".join(
                c["cve_id"] if isinstance(c, dict) else c.cve_id
                for c in item.cves[:2]
            )
            cve_str = f" {DIM}[{ids}]{RESET}"

        conf_color = {
            "HIGH": "\033[92m",
            "MEDIUM": "\033[93m",
            "LOW": "\033[91m",
        }.get(conf_val, "")

        conf_str = f"{conf_color}[Confidence: {conf_val}]{RESET}"
        prio_str = _priority_color(f"[{prio_val}]", prio_val)

        evidence_str = ""

        if item.evidence:
            evidence_str = f" {DIM}({'; '.join(item.evidence[:2])}){RESET}"

        host_str = f"{item.host:<15}" if item.host else " " * 15

        print(
            f"  {CYAN}{host_str}{RESET} "
            f"Port {item.port:>5} "
            f"({item.service:<16}) → "
            f"Risk: {_color(risk_val.upper(), risk_val):<20} "
            f"Score: {item.final_score}/5 {conf_str} {prio_str}{cve_str}"
            f"{evidence_str}"
        )

    ctx = report.context
    env_val = ctx.environment.value if hasattr(ctx.environment, "value") else str(ctx.environment)
    crit_val = ctx.criticality.value if hasattr(ctx.criticality, "value") else str(ctx.criticality)

    print(f"\n{BOLD}{'─' * 68}{RESET}")
    print(f"  Target            : {CYAN}{ctx.target}{RESET}")
    print(f"  Environment       : {env_val.upper()}")
    print(f"  Criticality       : {crit_val.upper()}")
    print(f"  Scan Mode         : {ctx.scan_mode}")
    print(f"  Source Tool       : {ctx.source_tool or 'ads'}")

    if ctx.source_file:
        print(f"  Source File       : {ctx.source_file}")

    print(f"  Mock              : {'ON' if ctx.mock else 'OFF'}")
    print(f"  Parallel          : {'ON' if ctx.parallel else 'OFF'}")
    print(f"  Workers           : {ctx.workers}")
    print(
        f"  Total             : {len(report.findings)} findings  "
        f"| {_color(str(report.high_count) + ' high', 'high')}  "
        f"| {_color(str(report.medium_count) + ' medium', 'medium')}  "
        f"| {_color(str(report.low_count) + ' low', 'low')}"
    )
    print(f"  Critical Priority : {_priority_color(str(report.critical_priority_count), 'CRITICAL')}")
    print(f"  High Priority     : {_priority_color(str(report.high_priority_count), 'HIGH')}")

    overall_risk = report.overall_risk
    overall_prio = report.overall_priority

    print(f"  Overall Risk      : {_color(overall_risk, overall_risk.lower())}")
    print(f"  Overall Priority  : {_priority_color(overall_prio, overall_prio)}")
    print(f"{BOLD}{'─' * 68}{RESET}\n")


def print_security_summary(context: ScanContext, findings: list) -> None:
    print(f"\n{BOLD}{'─' * 78}{RESET}")
    print(f"{BOLD}{'SECURITY FINDING RESULTS':^78}{RESET}")
    print(f"{BOLD}{'─' * 78}{RESET}")

    for item in findings:
        severity = item.severity.value.upper() if hasattr(item.severity, "value") else str(item.severity).upper()
        risk = item.risk.value.upper() if hasattr(item.risk, "value") else str(item.risk).upper()
        priority = item.priority.value.upper() if hasattr(item.priority, "value") else str(item.priority).upper()
        confidence = item.confidence.value.upper() if hasattr(item.confidence, "value") else str(item.confidence).upper()

        cve_text = ""
        if item.cve_ids:
            cve_text = f" {DIM}[{', '.join(item.cve_ids[:2])}]{RESET}"

        target = item.matched_at or item.host or "unknown-target"
        template = item.template_id or "unknown-template"
        name = item.name or "Unnamed finding"

        print(
            f"  {CYAN}{severity:<8}{RESET} "
            f"{template:<28} "
            f"→ Risk: {_color(risk, risk.lower()):<20} "
            f"Priority: {_priority_color(priority, priority)} "
            f"[Confidence: {confidence}]{cve_text}"
        )
        print(f"       Target : {target}")
        print(f"       Finding: {name}")

        if item.evidence:
            print(f"       Evidence: {'; '.join(item.evidence[:2])}")

    high_risk = sum(1 for item in findings if item.risk.value == "high")
    medium_risk = sum(1 for item in findings if item.risk.value == "medium")
    low_risk = sum(1 for item in findings if item.risk.value == "low")
    critical_priority = sum(1 for item in findings if item.priority.value == "critical")
    high_priority = sum(1 for item in findings if item.priority.value == "high")

    overall_risk = "HIGH" if high_risk else "MEDIUM" if medium_risk else "LOW"
    overall_priority = "CRITICAL" if critical_priority else "HIGH" if high_priority else "MEDIUM" if medium_risk else "LOW"

    env_val = context.environment.value if hasattr(context.environment, "value") else str(context.environment)
    crit_val = context.criticality.value if hasattr(context.criticality, "value") else str(context.criticality)

    print(f"\n{BOLD}{'─' * 78}{RESET}")
    print(f"  Target            : {CYAN}{context.target}{RESET}")
    print(f"  Environment       : {env_val.upper()}")
    print(f"  Criticality       : {crit_val.upper()}")
    print(f"  Scan Mode         : {context.scan_mode}")
    print(f"  Source Tool       : {context.source_tool or 'nuclei'}")

    if context.source_file:
        print(f"  Source File       : {context.source_file}")

    print(f"  Total             : {len(findings)} security findings")
    print(f"  High Risk         : {_color(str(high_risk), 'high')}")
    print(f"  Medium Risk       : {_color(str(medium_risk), 'medium')}")
    print(f"  Low Risk          : {_color(str(low_risk), 'low')}")
    print(f"  Critical Priority : {_priority_color(str(critical_priority), 'CRITICAL')}")
    print(f"  High Priority     : {_priority_color(str(high_priority), 'HIGH')}")
    print(f"  Overall Risk      : {_color(overall_risk, overall_risk.lower())}")
    print(f"  Overall Priority  : {_priority_color(overall_priority, overall_priority)}")
    print(f"{BOLD}{'─' * 78}{RESET}\n")


def _risk_text(value: str | None) -> str:
    if not value:
        return "?"

    return str(value).upper()


def _priority_text(value: str | None) -> str:
    if not value:
        return "?"

    return str(value).upper()


def _visible_diff_changes(diff_report) -> list:
    return [
        change
        for change in diff_report.changes
        if change.change_type in {"new", "removed", "risk_increased", "risk_decreased"}
    ]


def print_diff_summary(diff_report) -> None:
    s = diff_report.summary
    visible_changes = _visible_diff_changes(diff_report)

    print(f"\n{BOLD}{'─' * 78}{RESET}")
    print(f"{BOLD}{'SCAN DIFF':^78}{RESET}")
    print(f"{BOLD}{'─' * 78}{RESET}")

    if not visible_changes:
        print("  ✅ No new, removed, or risk-changed findings detected.")
        print(f"  Unchanged findings: {s.get('unchanged', 0)}")
        print(f"{BOLD}{'─' * 78}{RESET}\n")
        return

    for c in visible_changes:
        host = c.host if c.host else "?"
        port_proto = f"{c.port}/{c.protocol}"
        service = (c.service or "unknown")[:18]

        if c.change_type == "new":
            new_risk = _risk_text(c.new_risk)
            new_prio = _priority_text(c.new_priority)
            risk_colored = _color(new_risk, c.new_risk.lower() if c.new_risk else "low")
            prio_colored = _priority_color(f"[{new_prio}]", new_prio)

            print(
                f"  [NEW]       {host:<15} {port_proto:<9} {service:<18} "
                f"→ Risk: {risk_colored:<20} Priority: {prio_colored}"
            )

        elif c.change_type == "removed":
            old_risk = _risk_text(c.old_risk)
            old_prio = _priority_text(c.old_priority)
            risk_colored = _color(old_risk, c.old_risk.lower() if c.old_risk else "low")
            prio_colored = _priority_color(f"[{old_prio}]", old_prio)

            print(
                f"  [REMOVED]   {host:<15} {port_proto:<9} {service:<18} "
                f"→ Previous Risk: {risk_colored:<20} Priority: {prio_colored}"
            )

        elif c.change_type == "risk_increased":
            old_risk = _risk_text(c.old_risk)
            new_risk = _risk_text(c.new_risk)
            new_prio = _priority_text(c.new_priority)
            old_colored = _color(old_risk, c.old_risk.lower() if c.old_risk else "low")
            new_colored = _color(new_risk, c.new_risk.lower() if c.new_risk else "low")
            prio_colored = _priority_color(f"[{new_prio}]", new_prio)

            print(
                f"  [RISK ↑]    {host:<15} {port_proto:<9} {service:<18} "
                f"→ {old_colored} → {new_colored}  Priority: {prio_colored}"
            )

        elif c.change_type == "risk_decreased":
            old_risk = _risk_text(c.old_risk)
            new_risk = _risk_text(c.new_risk)
            new_prio = _priority_text(c.new_priority)
            old_colored = _color(old_risk, c.old_risk.lower() if c.old_risk else "low")
            new_colored = _color(new_risk, c.new_risk.lower() if c.new_risk else "low")
            prio_colored = _priority_color(f"[{new_prio}]", new_prio)

            print(
                f"  [RISK ↓]    {host:<15} {port_proto:<9} {service:<18} "
                f"→ {old_colored} → {new_colored}  Priority: {prio_colored}"
            )

    print(f"{BOLD}{'─' * 78}{RESET}")
    print(
        f"  Summary: "
        f"{s.get('new_ports', 0)} new, "
        f"{s.get('removed_ports', 0)} removed, "
        f"{s.get('risk_increased', 0)} risk increased, "
        f"{s.get('risk_decreased', 0)} risk decreased, "
        f"{s.get('unchanged', 0)} unchanged"
    )
    print(f"{BOLD}{'─' * 78}{RESET}\n")


def print_history() -> None:
    history = list_history()

    if not history:
        print("[ADS] No scan history found.")
        return

    print(f"\n{BOLD}Scan History (last 20):{RESET}")
    print(f"{'─' * 78}")

    for entry in history:
        target = entry.get("target", "unknown")
        environment = entry.get("environment", "unknown")
        criticality = entry.get("criticality", "unknown")
        scan_mode = entry.get("scan_mode", "unknown")
        source_tool = entry.get("source_tool", "")
        source_file = entry.get("source_file", "")
        timestamp = entry.get("timestamp", "unknown")
        path = entry.get("path", "unknown")
        size_kb = entry.get("size_kb", "?")
        index = entry.get("index", "?")

        print(f"  #{index:<3} {timestamp[:19]}  Target: {CYAN}{target}{RESET}")
        print(f"       Environment: {environment:<10} | Criticality: {criticality:<8} | Mode: {scan_mode}")

        if source_tool or source_file:
            source_text = source_tool if source_tool else "unknown"

            if source_file:
                source_text += f" ({source_file})"

            print(f"       Source: {source_text}")

        print(f"       {path}  ({size_kb} KB)")

    print(f"{'─' * 78}\n")


def load_findings_from_source(args: argparse.Namespace, is_subnet: bool) -> tuple[list, str]:
    if args.import_nmap_xml:
        print(f"[ADS] Import    : Nmap XML ({args.import_nmap_xml})")

        raw_findings = import_nmap_xml(args.import_nmap_xml)

        if args.target:
            target_label = args.target
        else:
            target_label = infer_target_label_from_findings(raw_findings, args.import_nmap_xml)

        return raw_findings, target_label

    if args.import_httpx_jsonl:
        print(f"[ADS] Import    : httpx JSONL ({args.import_httpx_jsonl})")

        raw_findings = import_httpx_jsonl(args.import_httpx_jsonl)

        if args.target:
            target_label = args.target
        else:
            target_label = infer_target_label_from_httpx_findings(raw_findings, args.import_httpx_jsonl)

        return raw_findings, target_label

    target = args.target

    if is_subnet and args.parallel:
        raw_findings = run_parallel_scan(
            subnet=target,
            max_workers=args.workers,
            mock=args.mock,
        )
    elif is_subnet and not args.parallel:
        print("[ADS] Warning: Subnet detected but --parallel was not provided.")
        raw_findings = run_scan(target, mock=args.mock)
    else:
        raw_findings = run_scan(target, mock=args.mock)

    return raw_findings, target


def load_security_findings_from_source(args: argparse.Namespace) -> tuple[list, str]:
    if args.import_nuclei_json:
        print(f"[ADS] Import    : Nuclei JSON/JSONL ({args.import_nuclei_json})")

        raw_findings = import_nuclei_json(args.import_nuclei_json)

        if args.target:
            target_label = args.target
        else:
            target_label = infer_target_label_from_nuclei_findings(raw_findings, args.import_nuclei_json)

        return raw_findings, target_label

    return [], ""


def handle_security_import(args: argparse.Namespace, scan_mode: str, source_tool: str, source_file: str) -> None:
    try:
        raw_security_findings, target_label = load_security_findings_from_source(args)
    except (OSError, ValueError) as e:
        # OSError covers FileNotFoundError, PermissionError, IsADirectoryError, etc.
        # ValueError covers parse/encoding failures raised from importers.
        print(f"[ADS] Import error: {e}")
        return

    if not raw_security_findings:
        print("[ADS] No importable security findings found.")
        return

    ctx = ScanContext(
        target=target_label,
        environment=Environment(args.environment),
        criticality=Criticality(args.criticality),
        mock=False,
        parallel=False,
        workers=args.workers,
        scan_mode=scan_mode,
        source_tool=source_tool,
        source_file=source_file,
    )

    analyzed_security_findings = analyze_security_findings(
        findings=raw_security_findings,
        environment=args.environment,
        criticality=args.criticality,
    )

    print_security_summary(ctx, analyzed_security_findings)

    # Route through unified ScanReport so the standard HTML + JSON reporters
    # render security findings alongside any port findings.
    report = ScanReport(
        context=ctx,
        findings=[],
        security_findings=analyzed_security_findings,
    )

    json_path = generate_json_report(report)
    if args.json:
        print(f"[ADS] JSON report           : {json_path}")

    if not args.no_html:
        html_path = generate_html_report(report)
        print(f"[ADS] HTML report           : {html_path}")

    # Legacy standalone security JSON, kept for backward compatibility.
    legacy_security_path = generate_security_json_report(ctx, analyzed_security_findings)
    if args.json:
        print(f"[ADS] Security JSON (legacy): {legacy_security_path}")

    save_latest_scan(json_path)

    print("\n[ADS] Security import completed.")


def main() -> None:
    print(BANNER)
    args = parse_args()

    if args.history:
        print_history()
        return

    if not validate_source_selection(args):
        return

    if not args.target and not args.import_nmap_xml and not args.import_httpx_jsonl and not args.import_nuclei_json:
        print("[ADS] Error: --target or an import source must be provided.")
        print("[ADS] Example: python main.py --target 192.168.1.1")
        print("[ADS] Example: python main.py --import-nmap-xml scans/nmap_result.xml")
        print("[ADS] Example: python main.py --import-httpx-jsonl test_data/httpx_import_test.jsonl")
        print("[ADS] Example: python main.py --import-nuclei-json test_data/nuclei_import_test.jsonl")
        return

    if (args.import_nmap_xml or args.import_httpx_jsonl or args.import_nuclei_json) and args.mock:
        print("[ADS] Warning: --mock is ignored in import mode.")

    is_subnet = is_valid_subnet(args.target) if args.target else False
    scan_mode = determine_scan_mode(args, is_subnet)
    source_tool, source_file = determine_source_info(args)

    print(f"[ADS] Target     : {args.target or 'imported-from-external-tool'}")
    print(f"[ADS] Environment: {args.environment}")
    print(f"[ADS] Criticality: {args.criticality}")
    print(f"[ADS] Mock mode  : {'ON' if args.mock and not (args.import_nmap_xml or args.import_httpx_jsonl or args.import_nuclei_json) else 'OFF'}")
    print(f"[ADS] Scan mode  : {scan_mode}")
    print(f"[ADS] Source     : {source_tool}")

    if source_file:
        print(f"[ADS] Source file: {source_file}")

    if args.parallel:
        print(f"[ADS] Parallel   : ON (workers: {args.workers})")

    if args.diff or args.compare:
        print(f"[ADS] Diff       : {args.diff or args.compare}")

    print()

    if args.import_nuclei_json:
        handle_security_import(args, scan_mode, source_tool, source_file)
        return

    try:
        raw_findings, target_label = load_findings_from_source(args, is_subnet)
    except (OSError, ValueError) as e:
        # OSError covers FileNotFoundError, PermissionError, IsADirectoryError, etc.
        # ValueError covers parse/encoding failures raised from importers.
        print(f"[ADS] Import error: {e}")
        return

    if not raw_findings:
        print("[ADS] No open ports or importable findings found.")
        return

    ctx = ScanContext(
        target=target_label,
        environment=Environment(args.environment),
        criticality=Criticality(args.criticality),
        mock=args.mock if not (args.import_nmap_xml or args.import_httpx_jsonl) else False,
        parallel=args.parallel if not (args.import_nmap_xml or args.import_httpx_jsonl) else False,
        workers=args.workers,
        scan_mode=scan_mode,
        source_tool=source_tool,
        source_file=source_file,
    )

    analyzed = analyze(
        findings=raw_findings,
        environment=args.environment,
        criticality=args.criticality,
    )

    for item in analyzed:
        fixes = generate_fixes(item)
        rules = generate_firewall_rules(item, args.environment)

        item.quick_fix = fixes.quick_fix
        item.proper_fix = fixes.proper_fix
        item.ufw_rule = rules.ufw
        item.iptables_rule = rules.iptables
        item.rule_note = rules.note
        item.priority = calculate_priority(item, args.environment, args.criticality)

    report = ScanReport(context=ctx, findings=analyzed)
    print_summary(report)

    json_path = generate_json_report(report)

    if args.json:
        print(f"[ADS] JSON report : {json_path}")

    save_latest_scan(json_path)

    if not args.no_html:
        html_path = generate_html_report(report)
        print(f"[ADS] HTML report : {html_path}")

    diff_source = args.diff or args.compare

    if diff_source:
        if diff_source == "last":
            previous_path = get_previous_scan_path()

            if previous_path is None:
                print("[ADS] Diff error: No previous scan found for comparison.")
                print("[ADS] Hint: You need at least 2 scans.")
            else:
                print(f"[ADS] Comparing with previous scan: {previous_path}")

                try:
                    diff_report = compare_scans(previous_path, json_path)
                    print_diff_summary(diff_report)

                    diff_html_path = generate_diff_html(diff_report)
                    print(f"[ADS] Diff report: {diff_html_path}")

                except FileNotFoundError as e:
                    print(f"[ADS] Diff error: {e}")

        else:
            try:
                diff_report = compare_scans(diff_source, json_path)
                print_diff_summary(diff_report)

                diff_html_path = generate_diff_html(diff_report)
                print(f"[ADS] Diff report: {diff_html_path}")

            except FileNotFoundError as e:
                print(f"[ADS] Diff error: {e}")

    print("\n[ADS] Scan completed.")


if __name__ == "__main__":
    main()