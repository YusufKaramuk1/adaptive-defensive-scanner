"""
ADS – Yardımcı Fonksiyonlar (helpers)
Proje genelinde kullanılan küçük araçlar.
"""

import re
import ipaddress
from datetime import datetime
from typing import List

from packaging import version as pkg_version


def is_valid_target(target: str) -> bool:
    """IP adresi veya hostname formatını doğrular."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    hostname_re = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(hostname_re.match(target)) or target == "localhost"


def is_valid_subnet(subnet_str: str) -> bool:
    """Geçerli bir IP ağı mı (CIDR) kontrol eder. /32 tek IP sayılmaz."""
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        if network.prefixlen == 32:
            return False
        return True
    except ValueError:
        return False


def expand_subnet(subnet_str: str) -> List[str]:
    """
    Bir subnet'i tüm host IP'lerine çevirir.
    Network ve broadcast adresleri hariç tutulur.
    Sadece IPv4 desteklenir.
    """
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return []

    if network.num_addresses > 256:
        print(
            f"[Helpers] Uyarı: Çok büyük subnet ({network.num_addresses} IP). "
            f"Bu uzun sürebilir. İlk 256 IP ile sınırlandırılıyor."
        )
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


def parse_version(version_str: str) -> str:
    """
    Ham versiyon string'ini temizler ve semantik benzeri hale getirir.

    Örnek:
      '2.4.49'  -> '2.4.49'
      '8.2p1'   -> '8.2'
      'OpenSSH_8.2p1' -> '8.2'
    """
    if not version_str:
        return ""

    raw = version_str.strip()

    match = re.search(r'(\d+(?:\.\d+)*)', raw)
    if match:
        return match.group(1)

    return raw


def version_in_range(version: str, constraint: str | tuple | list) -> bool:
    """
    Versiyonun belirtilen aralıkta olup olmadığını kontrol eder.

    constraint örnekleri:
      '>=2.4.49,<2.4.51'
      ('>=2.4.49', '<2.5')
      ['>=1.0', '<=2.0']
    """
    clean_version = parse_version(version)

    if not clean_version:
        return False

    try:
        parsed_version = pkg_version.parse(clean_version)

        if isinstance(constraint, str):
            parts = [part.strip() for part in constraint.split(",") if part.strip()]
            return all(_check_single_constraint(parsed_version, part) for part in parts)

        if isinstance(constraint, (tuple, list)):
            return all(_check_single_constraint(parsed_version, part) for part in constraint)

    except Exception:
        return False

    return False


def _check_single_constraint(parsed_version, constraint: str) -> bool:
    """Tek bir karşılaştırma operatörünü değerlendirir."""
    match = re.match(r'(>=|<=|!=|==|>|<)\s*(\S+)', constraint)

    if not match:
        return False

    operator, target = match.groups()
    target_version = pkg_version.parse(parse_version(target))

    if operator == ">=":
        return parsed_version >= target_version
    if operator == "<=":
        return parsed_version <= target_version
    if operator == "!=":
        return parsed_version != target_version
    if operator == "==":
        return parsed_version == target_version
    if operator == ">":
        return parsed_version > target_version
    if operator == "<":
        return parsed_version < target_version

    return False