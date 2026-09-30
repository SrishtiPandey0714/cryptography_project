from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# NIST P-256 curve
CURVE = ec.SECP256R1()


def generate_key_pair():
    """
    Generate an ECDH private/public key pair using P-256.

    Returns:
        private_key
        public_key
    """

    private_key = ec.generate_private_key(CURVE)
    public_key = private_key.public_key()

    return private_key, public_key


def save_private_key(private_key, filename):
    """
    Save a private key in PEM format.
    """

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(filename, "wb") as file:
        file.write(pem)


def save_public_key(public_key, filename):
    """
    Save a public key in PEM format.
    """

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filename, "wb") as file:
        file.write(pem)


def load_private_key(filename):
    """
    Load a private key from a PEM file.
    """

    with open(filename, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def load_public_key(filename):
    """
    Load a public key from a PEM file.
    """

    with open(filename, "rb") as file:
        return serialization.load_pem_public_key(
            file.read()
        )


def derive_shared_secret(private_key, peer_public_key):
    """
    Perform ECDH using our private key
    and the other person's public key.

    Returns:
        Shared secret bytes
    """
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )
    return shared_secret

def derive_keys(shared_secret):
    """
    Derive separate AES and HMAC keys from
    the ECDH shared secret using HKDF-SHA512.

    Returns:
        aes_key: 32 bytes
        hmac_key: 64 bytes
    """

    aes_key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=b"AES-256 encryption key"
    ).derive(shared_secret)

    hmac_key = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=None,
        info=b"HMAC-SHA512 authentication key"
    ).derive(shared_secret)

    return aes_key, hmac_key