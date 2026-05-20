"""
ADS – Subnet Expansion Test

This test verifies that utils/helpers.py correctly validates and expands
small CIDR subnet inputs.

Run:
    python test_subnet_expand.py
"""

from utils.helpers import is_valid_subnet, expand_subnet


def test_subnet_expand():
    subnet_30 = "192.168.1.0/30"
    hosts_30 = expand_subnet(subnet_30)

    assert is_valid_subnet(subnet_30) is True
    assert hosts_30 == ["192.168.1.1", "192.168.1.2"]

    print("✅ /30 subnet test passed.")

    subnet_29 = "192.168.1.0/29"
    hosts_29 = expand_subnet(subnet_29)

    assert is_valid_subnet(subnet_29) is True
    assert len(hosts_29) == 6
    assert hosts_29[0] == "192.168.1.1"
    assert hosts_29[-1] == "192.168.1.6"

    print("✅ /29 subnet test passed.")

    invalid_subnet = "not-a-subnet"

    assert is_valid_subnet(invalid_subnet) is False

    invalid_result = expand_subnet(invalid_subnet)

    assert invalid_result == []

    print("✅ Invalid subnet test passed.")

    print("\n✅ All subnet expansion tests passed.")


if __name__ == "__main__":
    test_subnet_expand()