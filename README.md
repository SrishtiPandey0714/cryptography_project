# Hybrid Secure Communication + ML Intrusion Detection System
---

## 1. System Highlights (Mapped to Presentation)
- **01 Secure Key Establishment**: ECDH on NIST P-256 (`SECP256R1`) + HKDF-SHA512 key derivation.
- **02 Confidential Communication**: AES-256-CTR with fresh 16-byte cryptographically secure nonces.
- **03 Integrity Verification**: HMAC-SHA512 over `nonce + ciphertext` with constant-time verification (`compare_digest`) *before* decryption.
- **04 ML Security Monitoring**: Real-time traffic profiling via `FlowMonitor` and Random Forest classification trained on UNSW-NB15 (`NORMAL` / `SUSPICIOUS` / `ATTACK`).

---

## 2. Environment Setup (Python 3.12 Required)

```powershell
# Windows (PowerShell):
py -3.12 -m venv .venv312
.\.venv312\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH="application;ml;crypto"
```

```bash
# macOS/Linux:
python3.12 -m venv .venv312
source .venv312/bin/activate
pip install -r requirements.txt
export PYTHONPATH="application:ml:crypto"
```

---

## 3. Launching the Interactive Web UI / Dashboard

Launch the complete interactive dashboard that visually replicates the presentation slides, key exchanges, live file transfers, attack injections, and ML metrics:

```powershell
streamlit run application/app.py
```

### Dashboard Features:
1. **🚀 File Transfer Tab**: Live Alice-to-Bob file encryption, transmission pacing, active bit-flip tampering, forged sender keys, and receiver gating.
2. **🚨 Security Threats Tab**: Direct replication of Slide 9 threats and live UDP flood attack generator triggering immediate `QUARANTINE`. Includes 1-click execution of all 6 Slide 11 scenarios.
3. **📊 ML Monitoring Tab**: Direct replication of Slide 10: Confusion matrix (`23,598 / 8,012 / 1,012 / 17,349`), 91.68% accuracy, 89.53% precision, 94.20% recall, 91.81% F1-score, and feature importance charts.
4. **🛡️ System Math Tab**: Complete mathematical derivations and LaTeX equations for ECDH P-256, HKDF-SHA512, AES-256-CTR, and HMAC-SHA512.

---

## 4. Running Verification Tests & CLI Demos

```powershell
# 1. Cryptographic layer tests (ECDH, HKDF, AES-CTR roundtrips, bit-flip detection)
python crypto/test_crypto.py

# 2. ML intrusion detection + integration unit tests (18 checks)
python ml/test_ml_layer.py

# 3. End-to-end 6-scenario demonstration table (Slide 11 benchmark)
python application/demo_ml_gate.py

# 4. Statistical tamper confusion matrix (1,500 trials)
python crypto/tamper_confusion_matrix.py
```

---

## 5. Observed System Actions (Slide 11 Matrix)

| Scenario / Threat | ML Gate Tier | HMAC Check | System Decision | Decrypted |
| :--- | :---: | :---: | :---: | :---: |
| **Legitimate Small File (4 KB)** | `NORMAL` | `True` | **`ACCEPT`** | ✅ Yes |
| **Legitimate Medium File (256 KB)** | `NORMAL` | `True` | **`ACCEPT`** | ✅ Yes |
| **Legitimate Large File (2 MB)** | `SUSPICIOUS` | `True` | **`ACCEPT_WITH_WARNING`** | ✅ Yes |
| **Tampered Ciphertext (Bit-Flip)** | `NORMAL` | `False` | **`REJECT_TAMPERED`** | ❌ Aborted |
| **Impostor Sender (Eve's Key)** | `NORMAL` | `False` | **`REJECT_TAMPERED`** | ❌ Aborted |
| **Volumetric UDP Flood** | `ATTACK` | `-` | **`QUARANTINE`** | 🛑 Zero Decrypt |

---

## 6. Directory Layout

```
crypto/        key_exchange.py, encryption.py, decryption.py, integrity.py, test_crypto.py
ml/            ids_detector.py, collect_app_flows.py, test_ml_layer.py, models/, results/
application/   app.py (Streamlit UI), secure_transfer.py, demo_ml_gate.py
notebooks/     crypto-ml-layer (1).ipynb (Kaggle EDA & training notebook)
```
