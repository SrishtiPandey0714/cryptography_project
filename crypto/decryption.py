from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

from integrity import verify_hmac


def decrypt_data(
    ciphertext,
    nonce,
    hmac_value,
    aes_key,
    hmac_key
):
    """
    Verify HMAC and decrypt ciphertext.

    Decryption only happens after successful
    HMAC verification.
    """

    # Recreate the data that was authenticated
    data_to_verify = nonce + ciphertext

    # Verify HMAC before decryption
    valid = verify_hmac(
        data_to_verify,
        hmac_value,
        hmac_key
    )

    if not valid:
        raise ValueError(
            "HMAC verification failed. "
            "Data may have been modified."
        )

    # Create AES-256-CTR cipher
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CTR(nonce)
    )

    decryptor = cipher.decryptor()

    # Decrypt ciphertext
    plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    return plaintext