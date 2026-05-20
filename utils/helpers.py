"""
ADS – Yardımcı Fonksiyonlar (helpers)
Proje genelinde kullanılan küçük araçlar.
"""

import re
import ipaddress
from datetime import datetime
from typing import List


def is_valid_target(target: str) -> bool:
    """IP adresi veya hostname formatını doğrular."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname (basit regex)
    hostname_re = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(hostname_re.match(target)) or target == "localhost"


def is_valid_subnet(subnet_str: str) -> bool:
    """Geçerli bir IP ağı mı (CIDR) kontrol eder."""
    try:
        ipaddress.ip_network(subnet_str, strict=False)
        return True
    except ValueError:
        return False


def expand_subnet(subnet_str: str) -> List[str]:
    """
    Bir subnet'i (örn: 192.168.1.0/24) tüm host IP'lerine çevirir.
    Network ve broadcast adresleri hariç tutulur.
    Sadece IPv4 desteklenir.
    """
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return []

    if network.num_addresses > 256:
        # Çok büyük subnet'leri sınırla (isteğe bağlı)
        print(f"[Helpers] Uyarı: Çok büyük subnet ({network.num_addresses} IP). "
              f"Bu uzun sürebilir. İlk 256 IP ile sınırlandırılıyor.")
        hosts = list(network.hosts())[:256]
    else:
        hosts = list(network.hosts())

    return [str(ip) for ip in hosts]


def normalize_service_name(service: str) -> str:
    """Servis adını küçük harfe normalize eder ve boşlukları temizler."""
    return service.lower().strip() if service else "unknown"


def timestamp_str(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """Dosya adı için timestamp üretir."""
    return datetime.now().strftime(fmt)


def clamp(value: int, min_val: int = 1, max_val: int = 5) -> int:
    """Değeri belirtilen aralığa sınırlar."""
    return max(min_val, min(value, max_val))


def format_port_range(ports: list[int]) -> str:
    """Port listesini okunabilir aralık string'ine çevirir."""
    return ", ".join(str(p) for p in sorted(set(ports)))