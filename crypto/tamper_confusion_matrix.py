"""
Crypto-layer verification: tamper-detection confusion matrix.

Treats the crypto layer's HMAC check as a binary detector and measures it empirically:
  Actual   = was the package really modified? (No / Yes)
  Predicted = did the receiver reject it?     (Accepted / Rejected)

Run from the repo root:   python crypto/tamper_confusion_matrix.py
Outputs:                  results/crypto_confusion_matrix.png, results/crypto_tamper_results.csv
"""
import os, random, hmac as _hmac
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

N_CLEAN, N_TAMPERED = 500, 1000     # trials per class
SEED = 42
random.seed(SEED)

# =====================================================================================
# ADAPTER: reference implementation of ECDH-P256 -> HKDF-SHA512 -> AES-256-CTR + HMAC-SHA512.
# To test your team's real code instead, replace the two functions below with thin wrappers
# around crypto/encryption.py and crypto/decryption.py. Keep the signatures.
#   encrypt_package(plaintext, sender_priv, receiver_pub) -> (ciphertext, nonce, tag)
#   verify_and_decrypt(ciphertext, nonce, tag, receiver_priv, sender_pub) -> plaintext or None
# =====================================================================================
def _derive(priv, peer_pub):
    shared = priv.exchange(ec.ECDH(), peer_pub)
    okm = HKDF(algorithm=hashes.SHA512(), length=96, salt=None,
               info=b"secure-file-transfer").derive(shared)
    return okm[:32], okm[32:]                      # AES-256 key, HMAC-SHA512 key

def _tag(mac_key, nonce, ct):
    h = hmac.HMAC(mac_key, hashes.SHA512()); h.update(nonce + ct); return h.finalize()

def encrypt_package(plaintext, sender_priv, receiver_pub):
    enc_key, mac_key = _derive(sender_priv, receiver_pub)
    nonce = os.urandom(16)
    enc = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct, nonce, _tag(mac_key, nonce, ct)

def verify_and_decrypt(ct, nonce, tag, receiver_priv, sender_pub):
    enc_key, mac_key = _derive(receiver_priv, sender_pub)
    if not _hmac.compare_digest(_tag(mac_key, nonce, ct), tag):   # constant-time compare
        return None                                               # REJECTED
    dec = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
    return dec.update(ct) + dec.finalize()

# ---------------- tamper operations (what an active attacker could do) ----------------
def flip_bit(b):
    b = bytearray(b); i = random.randrange(len(b)); b[i] ^= 1 << random.randrange(8); return bytes(b)

def t_ct_bit(ct, n, t, other):   return flip_bit(ct), n, t
def t_nonce_bit(ct, n, t, other):return ct, flip_bit(n), t
def t_tag_bit(ct, n, t, other):  return ct, n, flip_bit(t)
def t_truncate(ct, n, t, other): return ct[:-1], n, t
def t_append(ct, n, t, other):   return ct + os.urandom(1), n, t
def t_replace_ct(ct, n, t, other):  return os.urandom(len(ct)), n, t          # attacker substitutes data
TAMPERS = {"ciphertext bit-flip": t_ct_bit, "nonce bit-flip": t_nonce_bit, "HMAC tag bit-flip": t_tag_bit,
           "truncated ciphertext": t_truncate, "appended byte": t_append,
           "ciphertext replaced": t_replace_ct}

# ---------------- experiment ----------------
alice, bob = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
def new_msg(): return os.urandom(random.choice([16, 100, 1_000, 10_000, 65_536]))

TN = FP = TP = FN = 0
rows = []

for _ in range(N_CLEAN):                                    # untouched packages -> should be ACCEPTED
    m = new_msg(); ct, n, t = encrypt_package(m, alice, bob.public_key())
    out = verify_and_decrypt(ct, n, t, bob, alice.public_key())
    if out is not None and out == m: TN += 1
    else: FP += 1

per_type = {k: [0, 0] for k in TAMPERS}                     # [detected, total]
for i in range(N_TAMPERED):                                 # modified packages -> should be REJECTED
    name = list(TAMPERS)[i % len(TAMPERS)]
    m = new_msg(); ct, n, t = encrypt_package(m, alice, bob.public_key())
    ct2, n2, t2 = TAMPERS[name](ct, n, t, None)
    rejected = verify_and_decrypt(ct2, n2, t2, bob, alice.public_key()) is None
    per_type[name][1] += 1; per_type[name][0] += int(rejected)
    if rejected: TP += 1
    else: FN += 1

# wrong-key attacker (Eve) trying to forge a package for Bob: keys don't match -> must be rejected
eve = ec.generate_private_key(ec.SECP256R1()); forged = 0
for _ in range(200):
    m = new_msg(); ct, n, t = encrypt_package(m, eve, bob.public_key())      # Eve encrypts with HER key pair
    if verify_and_decrypt(ct, n, t, bob, alice.public_key()) is not None: forged += 1
per_type["forged by wrong key (Eve)"] = [200 - forged, 200]
TP += 200 - forged; FN += forged

# Replay: re-sending an old, UNMODIFIED package. HMAC gives integrity, not freshness -> accepted.
replay_accepted = 0
for _ in range(200):
    m = new_msg(); ct, n, t = encrypt_package(m, alice, bob.public_key())
    verify_and_decrypt(ct, n, t, bob, alice.public_key())                    # first delivery
    if verify_and_decrypt(ct, n, t, bob, alice.public_key()) is not None: replay_accepted += 1
print(f"Replay of a valid package accepted: {replay_accepted}/200  (known limitation: HMAC has no freshness check)")

cm = np.array([[TN, FP], [FN, TP]])
acc = (TN + TP) / cm.sum(); tpr = TP / (TP + FN); fpr = FP / (FP + TN)
print(f"TN={TN}  FP={FP}  FN={FN}  TP={TP}")
print(f"Accuracy={acc:.4f}  Detection rate (TPR)={tpr:.4f}  False-alarm rate (FPR)={fpr:.4f}")
tbl = pd.DataFrame([{"attack": k, "trials": v[1], "detected": v[0], "detection_rate": v[0] / v[1]}
                    for k, v in per_type.items()])
print(tbl.to_string(index=False))

# ---------------- figure ----------------
os.makedirs("results", exist_ok=True)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), gridspec_kw={"width_ratios": [1, 1.25]})
pct = cm / cm.sum(axis=1, keepdims=True) * 100
ax1.imshow(pct, cmap="Greens", vmin=0, vmax=100)
for i in range(2):
    for j in range(2):
        ax1.text(j, i, f"{cm[i, j]:,}\n({pct[i, j]:.1f}%)", ha="center", va="center", fontsize=13,
                 color="white" if pct[i, j] > 50 else "black")
ax1.set_xticks([0, 1]); ax1.set_xticklabels(["Accepted", "Rejected"])
ax1.set_yticks([0, 1]); ax1.set_yticklabels(["Untampered", "Tampered"])
ax1.set_xlabel("Receiver decision (predicted)"); ax1.set_ylabel("Actual package state")
ax1.set_title("HMAC-SHA512 tamper detection", fontweight="bold")

ax2.barh(tbl["attack"][::-1], tbl["detection_rate"][::-1] * 100, color="#2f855a")
ax2.set_xlim(0, 105); ax2.set_xlabel("Detection rate (%)"); ax2.set_title("Detection by attack type", fontweight="bold")
for y, (d, t) in enumerate(zip(tbl["detected"][::-1], tbl["trials"][::-1])):
    ax2.text(101, y, f"{d}/{t}", va="center", fontsize=9)
fig.suptitle(f"Crypto layer verification  |  accuracy {acc:.1%}, false-alarm rate {fpr:.1%}", fontsize=13)
fig.text(0.5, 0.01, f"Not counted above: replay of an unmodified package was accepted {replay_accepted}/200 times "
         "(HMAC gives integrity, not freshness; a sequence number or timestamp would fix this).",
         ha="center", fontsize=9, style="italic")
fig.tight_layout(rect=[0, 0.04, 1, 0.94])
fig.savefig("results/crypto_confusion_matrix.png", dpi=150)
tbl.loc[len(tbl)] = ["replay of valid package (not tampering)", 200, 200 - replay_accepted, (200 - replay_accepted) / 200]
tbl.to_csv("results/crypto_tamper_results.csv", index=False)
print("Saved results/crypto_confusion_matrix.png and results/crypto_tamper_results.csv")