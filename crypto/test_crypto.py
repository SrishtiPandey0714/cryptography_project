import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from key_exchange import (
    generate_key_pair,
    derive_shared_secret,
    derive_keys,
    save_private_key,
    save_public_key
)
from encryption import encrypt_file
from decryption import decrypt_data
from integrity import (
    generate_hmac,
    verify_hmac
)

print("Generating Alice's key pair...")

alice_private, alice_public = generate_key_pair()


print("Generating Bob's key pair...")

bob_private, bob_public = generate_key_pair()


print("\nSaving Alice's keys...")

save_private_key(
    alice_private,
    "keys/alice_private.pem"
)

save_public_key(
    alice_public,
    "keys/alice_public.pem"
)


print("Saving Bob's keys...")

save_private_key(
    bob_private,
    "keys/bob_private.pem"
)

save_public_key(
    bob_public,
    "keys/bob_public.pem"
)


print("\nCalculating Alice's shared secret...")

alice_secret = derive_shared_secret(
    alice_private,
    bob_public
)


print("Calculating Bob's shared secret...")

bob_secret = derive_shared_secret(
    bob_private,
    alice_public
)


print("\nAlice shared secret:")
print(alice_secret.hex())


print("\nBob shared secret:")
print(bob_secret.hex())


print("\nChecking whether the shared secrets match...")

if alice_secret == bob_secret:
    print("SUCCESS: Shared secrets match!")
else:
    print("ERROR: Shared secrets do not match!")
print("\nDeriving keys using HKDF-SHA512...")

alice_aes_key, alice_hmac_key = derive_keys(
    alice_secret
)

bob_aes_key, bob_hmac_key = derive_keys(
    bob_secret
)


print("\nChecking AES keys...")

if alice_aes_key == bob_aes_key:
    print("SUCCESS: AES keys match!")
else:
    print("ERROR: AES keys do not match!")


print("\nChecking HMAC keys...")

if alice_hmac_key == bob_hmac_key:
    print("SUCCESS: HMAC keys match!")
else:
    print("ERROR: HMAC keys do not match!")


print("\nKey lengths:")

print("AES key length:", len(alice_aes_key), "bytes")

print("HMAC key length:", len(alice_hmac_key), "bytes")

print("\nEncrypting sample.txt using AES-256-CTR...")

nonce = encrypt_file(
    "test_files/sample.txt",
    "encrypted_package/ciphertext.bin",
    alice_aes_key
)

print("AES encryption successful!")

print("Nonce generated successfully.")

with open(
    "encrypted_package/nonce.bin",
    "wb"
) as file:
    file.write(nonce)

print("Nonce saved successfully.")

print("\nGenerating HMAC-SHA512...")

with open("encrypted_package/ciphertext.bin", "rb") as file:
    ciphertext = file.read()

data_to_authenticate = nonce + ciphertext

hmac_value = generate_hmac(
    data_to_authenticate,
    alice_hmac_key
)

with open("encrypted_package/hmac.bin", "wb") as file:
    file.write(hmac_value)

print("HMAC generated successfully!")
print("HMAC length:", len(hmac_value), "bytes")


print("\nVerifying HMAC...")

is_valid = verify_hmac(
    data_to_authenticate,
    hmac_value,
    alice_hmac_key
)

if is_valid:
    print("SUCCESS: HMAC verification passed!")
else:
    print("ERROR: HMAC verification failed!")
print("\nDecrypting encrypted package...")

with open("encrypted_package/ciphertext.bin", "rb") as file:
    received_ciphertext = file.read()

with open("encrypted_package/nonce.bin", "rb") as file:
    received_nonce = file.read()

with open("encrypted_package/hmac.bin", "rb") as file:
    received_hmac = file.read()

decrypted_data = decrypt_data(
    received_ciphertext,
    received_nonce,
    received_hmac,
    bob_aes_key,
    bob_hmac_key
)

with open("test_files/decrypted.txt", "wb") as file:
    file.write(decrypted_data)

print("Decryption successful!")
print("\nComparing original and decrypted files...")

with open("test_files/sample.txt", "rb") as file:
    original_data = file.read()

with open("test_files/decrypted.txt", "rb") as file:
    decrypted_file_data = file.read()

if original_data == decrypted_file_data:
    print("SUCCESS: Original and decrypted files match!")
else:
    print("ERROR: Original and decrypted files do not match!")
    print("\nTesting ciphertext tampering...")

# Read the original ciphertext
with open("encrypted_package/ciphertext.bin", "rb") as file:
    tampered_ciphertext = bytearray(file.read())

# Change one byte
tampered_ciphertext[0] ^= 1

# Try to decrypt the modified ciphertext
try:
    decrypt_data(
        bytes(tampered_ciphertext),
        received_nonce,
        received_hmac,
        bob_aes_key,
        bob_hmac_key
    )

    print("ERROR: Tampered data was accepted!")

except ValueError as error:
    print("SUCCESS: Tampering detected!")
    print(error)
print("\nTesting HMAC tampering...")

tampered_hmac = bytearray(received_hmac)

# Change one byte of the HMAC
tampered_hmac[0] ^= 1

try:
    decrypt_data(
        received_ciphertext,
        received_nonce,
        bytes(tampered_hmac),
        bob_aes_key,
        bob_hmac_key
    )

    print("ERROR: Tampered HMAC was accepted!")

except ValueError as error:
    print("SUCCESS: HMAC tampering detected!")
    print(error)