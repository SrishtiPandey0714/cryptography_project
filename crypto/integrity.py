import hmac
import hashlib


def generate_hmac(data, key):
    """
    Generate an HMAC-SHA512 authentication tag.

    Args:
        data: Data that needs to be authenticated.
        key: HMAC secret key.

    Returns:
        HMAC-SHA512 digest as bytes.
    """

    return hmac.new(
        key,
        data,
        hashlib.sha512
    ).digest()


def verify_hmac(data, received_hmac, key):
    """
    Verify an HMAC-SHA512 authentication tag.

    Args:
        data: Original authenticated data.
        received_hmac: HMAC received with the encrypted package.
        key: HMAC secret key.

    Returns:
        True if HMAC is valid, otherwise False.
    """

    expected_hmac = generate_hmac(
        data,
        key
    )

    return hmac.compare_digest(
        expected_hmac,
        received_hmac
    )