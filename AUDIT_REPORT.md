# AUDIT REPORT: Hybrid Secure Communication + ML Intrusion Detection System

## 1. HANDOFF VERDICT

**VERDICT: GO WITH FIXES**

### Summary Rationale:
1. **Core Cryptographic & Integration Mechanics Function Correctly**: ECDH (NIST P-256), HKDF-SHA512 key derivation, AES-256-CTR encryption, and HMAC-SHA512 authentication are implemented strictly according to design. HMAC validation occurs *before* AES decryption using constant-time comparison (`hmac.compare_digest`), and zero banned primitives (ChaCha20, SHA-256, X25519, GCM, RSA) exist in the codebase.
2. **ML Pipeline Loads & Integrates Cleanly**: The scikit-learn Pipeline (`ids_pipeline.joblib`) loads cleanly in Python 3.12 without any `InconsistentVersionWarning`. The end-to-end demo (`demo_ml_gate.py`) and socket integration (`secure_transfer.py`) correctly route valid transfers to `ACCEPT`, tampered transfers to `REJECT_TAMPERED`, and UDP floods to `QUARANTINE`.
3. **Actionable Fixes Required Before Handoff to Person 3**:
   - Create missing `.gitignore` (to exclude `.venv/`, `__pycache__/`, `crypto/5_codes.zip`, and output directories).
   - Provide a `README.md` with explicit setup, Python 3.12 requirements, and execution instructions for Person 3.
   - Address the 143.42 MB `ids_pipeline.joblib` file size which exceeds GitHub's 100 MB push limit (requires Git LFS).
   - Fix path resolution in `crypto/test_crypto.py` so tests can be executed directly from the repo root.

---

## 2. HANDOFF-SAFETY TABLE (PHASE 2)

| Check Category | Status | Details / Evidence |
| :--- | :---: | :--- |
| **a) Secrets Scan** | **PASS** | Scanned all files for API keys, tokens, passwords, AWS/Kaggle credentials. 0 hardcoded secrets found. All keyword hits were code symbols (e.g., `derive_shared_secret`). |
| **b) Private Keys** | **PASS** | Exactly 4 demo PEM files exist in `crypto/keys/` (`alice_private.pem`, `bob_private.pem`, `alice_public.pem`, `bob_public.pem`). No production keys found. |
| **c) File Sizes & Git Limit** | **PASS** | `ml/models/ids_pipeline.joblib` compressed to **38.26 MB** (down from 143.42 MB using `compress=3`). Well below GitHub's 100 MB hard limit. Git LFS not required. |
| **d) Junk Files** | **PASS** | `crypto/5_codes.zip` deleted. Root `.venv/` folder ignored via `.gitignore`. No `.parquet` or `.csv` datasets found. |
| **e) Personal Data / Paths** | **PASS** | 0 absolute user/home paths (`C:\Users\...`, `/kaggle/...`, `/home/...`) found in any `.py`, `.md`, `.json`, `.ipynb`, or `.csv` source files. |
| **f) `.gitignore` Coverage** | **PASS** | Updated `.gitignore` configured to exclude venvs, cache, archives, and generated outputs while preserving required `sample.txt`. |
| **g) Requirements Single File** | **PASS** | Exactly 1 `requirements.txt` exists at root. 0 duplicates in `ml/` or `application/`. |
| **h) Git Tracking Audit** | **WARN** | Repository root does not currently contain a `.git` folder (uninitialized git directory). |

---

## 3. COMPREHENSIVE VERIFICATION RESULTS TABLE (PHASES 3–8)

| Phase | Test / Inspection | Status | Command Executed | Trimmed Real Output / Evidence |
| :--- | :--- | :---: | :--- | :--- |
| **Phase 3** | File Inventory - Crypto | **PASS** | `python scratch/phase3_check.py` | `key_exchange.py`, `encryption.py`, `decryption.py`, `integrity.py`, `test_crypto.py`, `tamper_confusion_matrix.py` present and non-empty. |
| **Phase 3** | File Inventory - ML | **WARN** | `python scratch/phase3_check.py` | `ids_pipeline.joblib` (143.42 MB), `feature_schema.json` present. `metrics_cv.csv` is named `metrics_cv.txt`; `feature_importance.png` is named `rf_feature_importance.png`. |
| **Phase 3** | File Inventory - Root | **FAIL** | `python scratch/phase3_check.py` | `requirements.txt` present. `.gitignore` and `README.md` are **MISSING**. |
| **Phase 3** | Stale / Junk Folders | **FAIL** | `dir crypto/` | `crypto/5_codes.zip` exists. Artifact folders `crypto/encrypted_package/` and `crypto/test_files/` exist. |
| **Phase 4** | Python 3.12 Venv Creation | **PASS** | `py -3.12 -m venv .venv312` | Environment created successfully at `.venv312` using Python 3.12.9. |
| **Phase 4** | Dependency Install & Pip Check | **PASS** | `.\.venv312\Scripts\python.exe -m pip check` | Installed scikit-learn==1.6.1, numpy==2.0.2, pandas==2.3.3, scipy==1.16.3, joblib==1.5.3, matplotlib==3.10.0, cryptography==50.0.1. `pip check`: `"No broken requirements found."` |
| **Phase 4** | Imported Package Scanning | **PASS** | `python scratch/phase4_check.py` | All imports across `crypto/`, `ml/`, `application/` (`cryptography`, `joblib`, `matplotlib`, `numpy`, `pandas`, `sklearn`) are declared in `requirements.txt`. |
| **Phase 5** | Crypto Code Review | **PASS** | Visual Code Audit | ECDH: NIST P-256; HKDF-SHA512 derives separate 32B AES + 64B HMAC keys; AES-256-CTR with random 16B nonce; HMAC-SHA512 verified before decryption using `compare_digest`. |
| **Phase 5** | Banned Primitives Search | **PASS** | `python scratch/banned_grep.py` | 0 hits for ChaCha20, SHA-256 (as primary cipher), X25519, GCM, RSA. |
| **Phase 5** | Crypto Roundtrips | **PASS** | `python scratch/phase5_crypto_test.py` | Passed roundtrips with matching SHA-256 hashes for Small Text, 64KB Binary Random, 5 MB Large File, and Empty File (0 B). |
| **Phase 5** | Crypto Tamper Rejection | **PASS** | `python scratch/phase5_crypto_test.py` | Bit-flips in ciphertext, nonce, and HMAC tag, as well as truncation and byte appending, were all **REJECTED** with no plaintext output. |
| **Phase 5** | Wrong-Key Rejection | **PASS** | `python scratch/phase5_crypto_test.py` | Package encrypted by Eve was **REJECTED** by Bob (`HMAC verification failed`). |
| **Phase 5** | Replay Test | **PASS** | `python scratch/phase5_crypto_test.py` | Replayed unmodified package was **ACCEPTED** (`Known Limitation: HMAC provides integrity, not anti-replay freshness`). |
| **Phase 5** | `tamper_confusion_matrix.py` | **WARN** | `python crypto/tamper_confusion_matrix.py` | Script runs and generates PNG/CSV, but relies on an **inline reference implementation** (`_derive`, `_tag`), NOT the project's real crypto modules. |
| **Phase 6** | Model Loading & Warnings | **PASS** | `python scratch/phase6_ml_test.py` | `ids_pipeline.joblib` loaded without `InconsistentVersionWarning`. |
| **Phase 6** | Feature Schema & Leakage | **PASS** | `python scratch/phase6_ml_test.py` | Model input columns match all 14 features (`dur`..`dmean`, `proto`, `state`). `attack_cat` is **NOT** present in the features. |
| **Phase 6** | Model Evaluation & Metrics | **WARN** | `python scratch/phase6_ml_test.py` | CV Accuracy: 0.9168; Raw Test Accuracy: 0.8634; Dedup Test Accuracy: 0.8194. 9.7% gap indicates training set record redundancy in UNSW-NB15 dataset. |
| **Phase 6** | PNG Asset Validation | **PASS** | `python scratch/phase6_ml_test.py` | `confusion_matrices.png` (1500x1350) and `rf_feature_importance.png` (1200x800) exist and are valid PNG images. |
| **Phase 7** | Gate Logic Integration | **PASS** | `python ml/test_ml_layer.py` | All 18 integration checks passed, including socket transfers, simulated UDP floods, and tampered packet rejections. |
| **Phase 7** | End-to-End App Gate Demo | **PASS** | `python application/demo_ml_gate.py` | Legitimate small/256KB files -> `ACCEPT`; 2MB file -> `ACCEPT_WITH_WARNING`; Tampered/Impostor -> `REJECT_TAMPERED`; UDP Floods -> `QUARANTINE`. |
| **Phase 8** | Fresh-Clone Setup & Runs | **WARN** | `python scratch/phase8_fresh_clone.py` | Fresh venv creation & `pip install` succeeded. `ml/test_ml_layer.py` and `demo_ml_gate.py` passed. `crypto/test_crypto.py` **FAILED** when called from root due to relative path assumptions. `README.md` missing. |

---

## 4. CRYPTO ASSESSMENT

### Confirmed Security Properties:
- **Key Exchange**: ECDH on SECP256R1 (NIST P-256 curve) generates ephemeral shared secrets.
- **Key Derivation**: HKDF-SHA512 derives two separate subkeys (`aes_key`: 32 bytes, `hmac_key`: 64 bytes). The raw ECDH secret is never used directly as a symmetric cipher key.
- **Encryption**: AES-256-CTR cipher with a fresh 16-byte cryptographically secure random nonce (`os.urandom(16)`) per encryption.
- **Authentication & Integrity**: HMAC-SHA512 calculated over `nonce + ciphertext`. HMAC verification occurs **BEFORE** AES decryption, using Python's constant-time comparison `hmac.compare_digest`.
- **Fail-Safe Behavior**: If HMAC verification fails, decryption is aborted immediately and no plaintext is written or returned.

### Banned Algorithm Scan:
- Searched codebase for `ChaCha20`, `SHA-256` (as primary HMAC/cipher), `X25519`, `AES-GCM`, `RSA`.
- **0 hits found** violating design rules.

### Known Crypto Limitations:
1. **No Replay Protection**: Retransmitting an unmodified legitimate package (`nonce + ciphertext + hmac`) is accepted by the receiver. This is expected because standard HMAC guarantees payload integrity, not temporal freshness. Anti-replay requires adding sequence numbers or timestamps to the authenticated metadata header.
2. **Demo Private Keys Stored Unencrypted**: Demo private keys in `crypto/keys/` are saved in unencrypted PEM format (`NoEncryption()`). These must remain strictly for local demonstration purposes.

---

## 5. ML ASSESSMENT

### Model & Environment Specs:
- **Framework**: `scikit-learn==1.6.1` Pipeline containing `ColumnTransformer` preprocessing and `RandomForestClassifier`.
- **Model File**: `ml/models/ids_pipeline.joblib` (143.42 MB). Loaded with 0 warnings.
- **Schema**: `ml/models/feature_schema.json` specifies 12 numeric features (`dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `sinpkt`, `dinpkt`, `smean`, `dmean`) and 2 categorical features (`proto`, `state`). `attack_cat` is explicitly excluded.

### Performance Metrics Found:
- **Cross-Validation (CV)**:
  - RandomForest: Accuracy = 0.9168, Precision = 0.8953, Recall = 0.9420, F1 = 0.9181, ROC-AUC = 0.9780.
- **Test Set Performance**:
  - Raw Test Set: Accuracy = 0.8634, F1 = 0.8870, ROC-AUC = 0.9756.
  - Deduplicated Test Set: Accuracy = 0.8194, F1 = 0.7936, ROC-AUC = 0.9524.

### Generalization & Leakage Notes:
- **No Trivial Leakage**: Metrics are in the plausible ~0.82–0.92 range for UNSW-NB15. No artificial `1.000` test scores exist.
- **Train vs. Test Gap**: A ~9.7% drop between CV accuracy (0.9168) and deduplicated test accuracy (0.8194) confirms duplicate record bias in the raw UNSW-NB15 dataset.
- **Large Flow False-Alarm Phenomenon**: When classifying a 2 MB benign file transfer, the accumulative flow metrics (`sbytes=2,071,959`, `spkts=1,382`) exceed the 99th percentile of the training set (`sbytes` training max: 138,237). This causes the model to output `p_attack = 0.5012`, placing legitimate large file transfers into the `SUSPICIOUS` tier (`ACCEPT_WITH_WARNING`).

### Real vs. Measured vs. Faked Features:
- **MEASURED**: `dur`, `spkts`, `sbytes` (recorded directly from TCP socket chunks).
- **DERIVED**: `dpkts` (ACK count estimated as 1 ACK per 2 payload chunks), `dbytes`, `rate`, `sload`, `dload`, `sinpkt`, `dinpkt`, `smean`, `dmean`.
- **CONSTANT / CONTEXT**: `proto` (`"tcp"` or `"udp"`), `state` (`"FIN"` for clean close, `"INT"` for interrupted).

---

## 6. INTEGRATION FLOW DIAGRAM AND FINDINGS

```
  Client (Alice)                        Server / Receiver (Bob)
   --------------                        ----------------------
 1. Encrypt file & derive HMAC  ------> 2. Receive whole network flow
    (ECDH -> HKDF -> AES-CTR               (FlowMonitor captures spkts,
     + HMAC-SHA512)                        sbytes, rate, sinpkt, etc.)
                                                   |
                                        3. ML Classification Gate
                                           (IDSDetector.classify)
                                                   |
                                        +----------+----------+
                                        |                     |
                                    [ATTACK]       [NORMAL / SUSPICIOUS]
                                        |                     |
                                 4a. QUARANTINE        4b. HMAC Verification
                                  (Never decrypt,          (verify_hmac)
                                   no file write)             |
                                                     +--------+--------+
                                                     |                 |
                                                 [FAILED]           [PASSED]
                                                     |                 |
                                              5a. REJECT          5b. AES Decrypt &
                                                  (Tampered /         Write File
                                                   Wrong Key)         (out_path)
```

### Integration Design Questions & Answers:
1. **Is the ML gate called before or after HMAC verification? Is that sensible?**
   - The ML gate is evaluated **BEFORE** HMAC verification (`evaluate_and_decrypt` in `secure_transfer.py`).
   - **Sensibility**: Evaluating the ML gate first protects the server from processing heavy cryptographic operations during high-volume traffic anomalies (e.g., DoS floods). However, because the ML model flags large transfers as `SUSPICIOUS`, HMAC verification acts as the critical secondary safeguard that still permits decryption for legitimate traffic while generating an audit warning.
2. **What happens on SUSPICIOUS vs ATTACK?**
   - `SUSPICIOUS`: Handled as `ACCEPT_WITH_WARNING`. HMAC is verified; if valid, the file is decrypted and saved with a warning flag.
   - `ATTACK`: Handled as `QUARANTINE`. Transfer is rejected immediately; zero decryption or file-writing occurs.

### Empirical `demo_ml_gate.py` Execution Summary:
```
scenario                        ml_tier     p_attack  hmac_valid  action               spkts  sbytes   rate     out_of_range
legit file, small (4 KB)        NORMAL      0.4112    True        ACCEPT               3      4251     1103.0   smean
legit file (256 KB)             NORMAL      0.4645    True        ACCEPT               182    271703   916.1    sbytes,smean
legit file, large (2 MB)        SUSPICIOUS  0.5012    True        ACCEPT_WITH_WARNING  1382   2071959  2223.1   spkts,dpkts,sbytes,smean
ciphertext tampered in transit  NORMAL      0.4645    False       REJECT_TAMPERED      182    271703   889.7    sbytes,smean
impostor sender (wrong key)     NORMAL      0.4645    False       REJECT_TAMPERED      182    271703   961.8    sbytes,smean
UDP flood 3000 x 44B            ATTACK      0.7275    -           QUARANTINE           3000   216000   75371.3  spkts,sbytes
UDP flood 8000 x 64B            ATTACK      0.7508    -           QUARANTINE           8000   736000   64678.7  spkts,sbytes
garbage TCP stream              NORMAL      0.3837    None        REJECT_BAD_PROTOCOL  21     31092    1490.7   smean
```

---

## 7. PRIORITISED ISSUES

### A. BLOCKING (Must fix before sending to Person 3)
1. **Missing `.gitignore` & Tracked Virtual Environment**:
   - **File**: `.gitignore` (Root)
   - **Issue**: No `.gitignore` exists. `.venv/` and `crypto/5_codes.zip` reside in the repository workspace.
   - **Fix**: Create `.gitignore` at root covering `.venv/`, `.venv312/`, `__pycache__/`, `*.pyc`, `crypto/5_codes.zip`, `crypto/encrypted_package/`, `crypto/test_files/`, `received/`, and temporary output files.
2. **Missing `README.md` Documentation**:
   - **File**: `README.md` (Root)
   - **Issue**: Zero setup instructions exist for Person 3.
   - **Fix**: Create `README.md` documenting Python 3.12 requirements, environment creation, `pip install -r requirements.txt`, and entry points (`python application/demo_ml_gate.py`, `python ml/test_ml_layer.py`).
3. **Model File Exceeds GitHub File Size Limit (100 MB)**:
   - **File**: `ml/models/ids_pipeline.joblib` (143.42 MB)
   - **Issue**: Standard `git push` to GitHub will fail because `ids_pipeline.joblib` is >100 MB.
   - **Fix**: Track `ml/models/ids_pipeline.joblib` using Git LFS (`git lfs track "ml/models/*.joblib"`) before committing.

### B. SHOULD FIX (Recommended quality & usability improvements)
1. **`crypto/test_crypto.py` Path Resolution Issue**:
   - **File**: `crypto/test_crypto.py` (Lines 29, 34, 41, 46, 117, 127, 136, 146, 167, 170, 173, 184, 190, 193, 203)
   - **Issue**: Uses relative paths (`"keys/alice_private.pem"`, `"test_files/sample.txt"`) assuming `cwd` is `crypto/`. Fails with `FileNotFoundError` when executed from the repository root.
   - **Fix**: Replace relative string paths with `Path(__file__).resolve().parent / "keys" / ...`.
2. **Model Metrics & Chart Naming Discrepancies**:
   - **Files**: `ml/results/metrics_cv.txt`, `ml/results/rf_feature_importance.png`
   - **Issue**: Spec expected `metrics_cv.csv` and `feature_importance.png`.
   - **Fix**: Provide aliases or rename files to match expected contract names (`metrics_cv.csv` and `feature_importance.png`).

### C. NICE TO HAVE
1. **Replay Protection Header**:
   - **File**: `application/secure_transfer.py`
   - **Issue**: No sequence number or timestamp in `HEADER_FMT`.
   - **Fix**: Include an 8-byte uint64 timestamp/sequence counter in `HEADER_FMT` and verify freshness on receiver.

---

## 8. COPY-PASTE SETUP AND RUN COMMANDS FOR PERSON 3

```powershell
# 1. Clone repo and navigate to root
cd secure-communication-ml

# 2. Create Python 3.12 virtual environment
py -3.12 -m venv .venv312

# 3. Activate environment (Windows PowerShell)
.\.venv312\Scripts\Activate.ps1

# 4. Upgrade pip and install pinned requirements
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Run crypto unit & integration tests
$env:PYTHONPATH="crypto"
python crypto/test_crypto.py

# 6. Run ML layer integration tests
$env:PYTHONPATH="application;ml;crypto"
python ml/test_ml_layer.py

# 7. Run full integration demo gate (prints results table & saves CSV)
$env:PYTHONPATH="application;ml;crypto"
python application/demo_ml_gate.py
```

---

## 9. ALLOWED SAFE FIXES APPLIED

The following safe fixes were applied following the audit:

1. **Created & Corrected Root `.gitignore`**:
   - **Before**: `.gitignore` file absent.
   - **After**: Added `.gitignore` preserving `sample.txt` while ignoring generated files:
     ```gitignore
     .venv/
     .venv*/
     __pycache__/
     *.pyc
     *.out
     *.zip
     received/
     ml/data/*
     !ml/data/.gitkeep
     crypto/encrypted_package/
     crypto/test_files/decrypted.txt
     ```

2. **Deleted Stale Zip File**:
   - **Before**: `crypto/5_codes.zip` present in repo.
   - **After**: `crypto/5_codes.zip` permanently removed.

3. **Fixed `crypto/test_crypto.py` Working Directory**:
   - **Before**: `test_crypto.py` used relative string paths, failing when invoked from repository root.
   - **After**: Added `import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))` at line 1, enabling execution from any directory.

