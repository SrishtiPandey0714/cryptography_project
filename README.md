# Hybrid Secure Communication + ML Intrusion Detection

Secure file transfer: ECDH (P-256) -> HKDF-SHA512 -> AES-256-CTR + HMAC-SHA512,
with an ML gate (Random Forest trained on UNSW-NB15) that classifies each transfer's
network flow as NORMAL / SUSPICIOUS / ATTACK.

## Setup (Python 3.12 required; numpy 2.0.2 has no wheels for 3.13/3.14)

Windows (PowerShell):
    py -3.12 -m venv .venv312
    .\.venv312\Scripts\Activate.ps1
    pip install -r requirements.txt
    $env:PYTHONPATH="application;ml;crypto"

macOS/Linux:
    python3.12 -m venv .venv312
    source .venv312/bin/activate
    pip install -r requirements.txt
    export PYTHONPATH="application:ml:crypto"

scikit-learn is pinned to 1.6.1 because the saved model was trained with it.

## Run
    python crypto/test_crypto.py          # crypto tests
    python ml/test_ml_layer.py            # ML layer + integration checks
    python application/demo_ml_gate.py    # end-to-end demo table

## Layout
    crypto/        key exchange, encryption, decryption, integrity, tests
    ml/            ids_detector.py, models/ (trained pipeline + feature_schema.json), results/
    application/   secure_transfer.py, demo_ml_gate.py  (integration skeleton)

## Notes for the integration lead
- The model is ONE pipeline (preprocessing + classifier). Feed it a DataFrame with the
  14 columns in ml/models/feature_schema.json.
- Currently the ML gate runs BEFORE HMAC verification. ATTACK -> quarantined, never decrypted.
  SUSPICIOUS -> accepted with warning after HMAC passes.
- Known limitations: no replay protection (HMAC = integrity, not freshness); demo private
  keys are unencrypted; very large transfers fall outside UNSW-NB15's feature range.
- Dataset (not in repo): UNSW-NB15 parquet, Kaggle dataset "dhoogla/unswnb15".