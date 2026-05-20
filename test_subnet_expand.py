#!/usr/bin/env python3
"""
Subnet Expand Test
Subnet'ten IP listesi oluşturmayı doğrular.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from utils.helpers import expand_subnet


def test_subnet():
    # 1. /30 subnet (4 adres, 2 kullanılabilir host)
    ips = expand_subnet("192.168.1.0/30")
    expected = ["192.168.1.1", "192.168.1.2"]
    assert ips == expected, f"/30 başarısız: {ips}"
    print("✅ /30 testi geçti")

    # 2. /29 subnet (8 adres, 6 host)
    ips = expand_subnet("10.0.0.0/29")
    assert len(ips) == 6, f"/29 host sayısı yanlış: {len(ips)}"
    assert "10.0.0.0" not in ips and "10.0.0.7" not in ips
    print("✅ /29 testi geçti")

    # 3. Geçersiz subnet
    ips = expand_subnet("invalid")
    assert ips == [], f"Geçersiz subnet boş dönmeli: {ips}"
    print("✅ Geçersiz subnet testi geçti")

    print("\n✅ Tüm testler başarılı.")


if __name__ == "__main__":
    test_subnet()