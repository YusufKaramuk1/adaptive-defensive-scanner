"""
ADS – JSON Exporter (reporter)
Makine tarafından okunabilir JSON raporu üretir.
SIEM entegrasyonu, history/diff ve ileride API/dashboard için kullanılabilir.
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanReport


def generate_json_report(report: ScanReport) -> str:
    """
    ScanReport nesnesini JSON olarak üretir ve dosyaya yazar.

    Dönen değer:
        str: oluşturulan JSON rapor dosyasının yolu
    """
    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"ads_report_{timestamp}.json"

    payload = {
        "meta": {
            "tool":      "Adaptive Defensive Scanner (ADS)",
            "version":   "2.5",
            "generated": now.isoformat(),
        },
        **report.to_dict(),
    }

    report_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"[Reporter] JSON report created: {report_path}")
    return str(report_path)