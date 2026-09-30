import os

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using AES-256-CTR.

    Args:
        input_file: Path to plaintext file.
        output_file: Path where ciphertext will be saved.
        key: 32-byte AES-256 key.

    Returns:
        The nonce used for encryption.
    """

    # Generate a random 16-byte nonce/counter.
    nonce = os.urandom(16)

    # Create AES-CTR cipher.
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )

    encryptor = cipher.encryptor()

    # Read plaintext.
    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Encrypt plaintext.
    ciphertext = (
        encryptor.update(plaintext)
        + encryptor.finalize()
    )

    # Save ciphertext.
    with open(output_file, "wb") as file:
        file.write(ciphertext)

    return nonce