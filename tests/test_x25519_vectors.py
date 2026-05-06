"""
Tests for the core X25519 implementation.

These tests use known X25519 test vectors.

Why this is important:
    A cryptographic implementation should not only "seem to work".
    It should be checked against known input/output pairs.

If our x25519() function produces the expected output for these vectors,
it gives strong evidence that the Montgomery ladder and encoding logic are
implemented correctly.
"""

from src.x25519 import x25519


def test_x25519_official_test_vector_1():
    """
    Test X25519 against a known test vector.

    This test checks:
        x25519(private_key, public_key) == expected_result

    If this fails, the problem is probably in one of:
        - scalar clamping
        - u-coordinate decoding
        - Montgomery ladder formulas
        - byte order conversion
    """
    private_key = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd"
        "62144c0ac1fc5a18506a2244ba449ac4"
    )

    public_key = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c"
    )

    expected = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f"
        "32eccf03491c71f754b4075577a28552"
    )

    assert x25519(private_key, public_key) == expected


def test_x25519_official_test_vector_2():
    """
    Test X25519 against a second known test vector.

    Using more than one test vector is useful because it reduces the chance
    that the implementation only works accidentally for one specific input.
    """
    private_key = bytes.fromhex(
        "4b66e9d4d1b4673c5ad22691957d6af"
        "5c11b6421e0ea01d42ca4169e7918ba0d"
    )

    public_key = bytes.fromhex(
        "e5210f12786811d3f4b7959d0538ae2c"
        "31dbe7106fc03c3efc4cd549c715a493"
    )

    expected = bytes.fromhex(
        "95cbde9476e8907d7aade45cb4b873f8"
        "8b595a68799fa152e6f8f7647aac7957"
    )

    assert x25519(private_key, public_key) == expected