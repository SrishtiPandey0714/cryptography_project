# PERSON 3 INTEGRATION & RELEASE HANDOFF GUIDE
## Hybrid Secure Communication + ML Intrusion Detection System

---

## 1. EXECUTIVE SUMMARY & ROLE OF PERSON 3

Welcome! As **Person 3 (Integration & UI Lead)**, your core responsibility is to take the modules produced by **Person 1 (Crypto Lead)** and **Person 2 (ML Lead)**, integrate them into a complete working application, build a user-facing UI/Dashboard (recommended: Streamlit), run end-to-end attack/performance testing, and coordinate the final presentation and report.

```
                  ┌─────────────────────────────────────────┐
                  │               PERSON 3                  │
                  │       (Integration & UI Lead)           │
                  └────────────────────┬────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ Person 1 Crypto │           │  Person 2 ML    │           │ Application /   │
│  (P-256 ECDH,   │           │ (RandomForest   │           │ UI & Dashboard  │
│ AES-CTR, HMAC)  │           │   Pipeline)     │           │  (Streamlit)    │
└────────┬────────┘           └────────┬────────┘           └────────┬────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │    Complete Integrated Demo    │
                       │  + Report + Presentation PPT  │
                       └───────────────────────────────┘
```

---

## 2. CURRENT CODEBASE VS. FIRST-DRAFT WORKFLOW (CRITICAL)

> [!IMPORTANT]
> **Do not re-invent the architecture!** The foundational glue code, binary wire protocol, ML flow monitoring, and gating logic are **already fully built and tested** in `application/secure_transfer.py` and `application/demo_ml_gate.py`.

### Key Differences: Draft Ideas vs. Current Reality

| Feature | First Draft Idea | Current Actual Implementation |
| :--- | :--- | :--- |
| **Crypto Code** | Raw crypt primitives passed manually | Handled by `crypto/key_exchange.py`, `encryption.py`, `decryption.py`, `integrity.py`. |
| **Wire Protocol** | Custom text / JSON parameters | Binary protocol (`MAGIC = b"SFT1"`, `Package` dataclass in `secure_transfer.py`). |
| **ML Gate Flow** | Run after transfer or raw packet capture | `FlowMonitor` profiles live socket bytes -> `IDSDetector` classifies -> `evaluate_and_decrypt()` gates crypto. |
| **Gate Sequence** | ML after HMAC | **ML Gate runs FIRST**. If `ATTACK`, payload is **QUARANTINED** immediately (decryption never attempted). |
| **Large File Behavior** | Assumed normal | Transfers > 2MB exceed UNSW-NB15 training limits; model assigns `SUSPICIOUS` tier -> system outputs `ACCEPT_WITH_WARNING` after HMAC verification passes. |
| **Integration Entrypoint** | Manual socket loops | `st.evaluate_and_decrypt()`, `st.prepare_package()`, `st.send_wire()`, `st.simulate_udp_flood()`. |

---

## 3. TECHNICAL API REFERENCE FOR INTEGRATION

### A. Crypto API (Person 1's Code in `crypto/`)
- `generate_key_pair()`: Returns `(private_key, public_key)` using NIST P-256 (`SECP256R1`).
- `derive_shared_secret(priv, peer_pub)`: Performs ECDH key exchange.
- `derive_keys(shared_secret)`: Uses HKDF-SHA512 to return `(aes_key [32B], hmac_key [64B])`.
- `encrypt_file(input_path, output_path, aes_key)`: AES-256-CTR encrypts file; returns 16-byte `nonce`.
- `generate_hmac(nonce + ciphertext, hmac_key)`: Generates 64-byte HMAC-SHA512 tag.
- `decrypt_data(ciphertext, nonce, hmac_tag, aes_key, hmac_key)`: Constant-time verify (`compare_digest`) before AES-256-CTR decryption. Raises `ValueError` on tamper.

### B. ML API (Person 2's Code in `ml/`)
- `FlowMonitor(proto="tcp"|"udp")`:
  - `.record_src(payload_len)`: Records outgoing payload chunk + transport header overhead (52B for TCP, 28B for UDP).
  - `.features()`: Generates 14 feature dictionary (`dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `sinpkt`, `dinpkt`, `smean`, `dmean`, `proto`, `state`). *Note: TCP ACKs are derived as 1 ACK per 2 payload chunks.*
- `IDSDetector(model_dir="ml/models")`:
  - `.classify(feats)`: Returns `{"tier": "NORMAL"|"SUSPICIOUS"|"ATTACK", "attack_probability": float, "out_of_range_features": [...]}` based on thresholds `t_suspicious=0.4697` and `t_attack=0.5234`.

### C. Application Glue API (`application/secure_transfer.py`)
- `Package(nonce, hmac, ciphertext)`: Dataclass. Supports `.to_wire()` and `.from_wire(bytes)`.
- `prepare_package(input_file, sender_private, receiver_public)`: Builds `Package` in 1 call.
- `evaluate_and_decrypt(package, monitor, detector, receiver_private, sender_public, out_path)`:
  1. Calls `detector.classify(monitor.features())`.
  2. If `tier == "ATTACK"` $\rightarrow$ Returns `action="QUARANTINE"` (Decryption blocked).
  3. Checks `verify_hmac()`. If invalid $\rightarrow$ Returns `action="REJECT_TAMPERED"`.
  4. Decrypts via `decrypt_data()`. If `NORMAL` $\rightarrow$ `action="ACCEPT"`; If `SUSPICIOUS` $\rightarrow$ `action="ACCEPT_WITH_WARNING"`.
- `simulate_udp_flood(detector, n=3000, size=44)`: Generates synthetic UDP flood against local monitor for demo buttons.

---

## 4. UI & DASHBOARD IMPLEMENTATION BLUEPRINT (STREAMLIT)

For Person 3's UI, we recommend creating `application/app.py` using **Streamlit**.

### Recommended File Structure for Person 3
```
application/
├── secure_transfer.py      # Core glue & wire protocol (existing)
├── demo_ml_gate.py         # Terminal benchmark script (existing)
├── app.py                  # Streamlit Dashboard UI (TO BUILD)
└── ui_components.py        # Custom styling & cards (optional)
```

### Complete Code Template for `application/app.py`

```python
import streamlit as st
import os, sys, tempfile, Path
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "application"))
sys.path.insert(0, str(ROOT / "crypto"))
sys.path.insert(0, str(ROOT / "ml"))

import secure_transfer as st_lib
from key_exchange import generate_key_pair
from ids_detector import IDSDetector

st.set_page_config(page_title="Secure File Transfer + ML IDS", layout="wide", page_icon="🛡️")

st.title("🛡️ Hybrid Secure Communication + ML Intrusion Detection System")
st.markdown("---")

# Sidebar: System Configuration & Keys
st.sidebar.header("🔑 Session Keys & Setup")
if "alice_priv" not in st.session_state:
    st.session_state.alice_priv, st.session_state.alice_pub = generate_key_pair()
    st.session_state.bob_priv, st.session_state.bob_pub = generate_key_pair()
    st.session_state.eve_priv, st.session_state.eve_pub = generate_key_pair()
    st.session_state.detector = IDSDetector(ROOT / "ml" / "models")

st.sidebar.success("ECDH P-256 Keypairs Generated")
st.sidebar.info(f"ML Model: {st.session_state.detector.schema['model']} (Sklearn 1.6.1)")

# Main Tabs
tab1, tab2, tab3 = st.tabs(["🚀 File Transfer", "🚨 Attack Demonstration", "📊 Model & Performance Metrics"])

with tab1:
    st.header("Secure File Transfer (Alice ➔ Bob)")
    uploaded_file = st.file_uploader("Select File to Transfer", type=["txt", "pdf", "png", "jpg", "bin"])
    
    col1, col2 = st.columns(2)
    with col1:
        tamper_ct = st.checkbox("Simulate Transit Ciphertext Tampering (Bit-Flip)")
        use_wrong_key = st.checkbox("Simulate Impostor Sender (Eve's Key)")
    
    if uploaded_file and st.button("Encrypt & Send File"):
        with tempfile.TemporaryDirectory() as td:
            in_path = Path(td) / uploaded_file.name
            out_path = Path(td) / f"decrypted_{uploaded_file.name}"
            in_path.write_bytes(uploaded_file.getvalue())
            
            sender_priv = st.session_state.eve_priv if use_wrong_key else st.session_state.alice_priv
            pkg = st_lib.prepare_package(in_path, sender_priv, st.session_state.bob_pub)
            
            if tamper_ct:
                w = bytearray(pkg.ciphertext)
                w[0] ^= 1
                pkg.ciphertext = bytes(w)
                
            mon = st_lib.FlowMonitor("tcp")
            for i in range(0, len(pkg.ciphertext), 1448):
                mon.record_src(min(1448, len(pkg.ciphertext) - i))
            mon.close(True)
            
            res = st_lib.evaluate_and_decrypt(pkg, mon, st.session_state.detector, 
                                             st.session_state.bob_priv, st.session_state.alice_pub, out_path)
            
            st.subheader("Transfer Result")
            action = res["action"]
            if action == "ACCEPT":
                st.success(f"✅ ACCEPTED: File transferred and verified cleanly. Path: {out_path.name}")
            elif action == "ACCEPT_WITH_WARNING":
                st.warning(f"⚠️ ACCEPTED WITH WARNING: HMAC valid, but ML flagged flow as SUSPICIOUS.")
            elif action == "REJECT_TAMPERED":
                st.error(f"🚨 REJECTED: HMAC Verification Failed! (Data modified or wrong key used).")
            elif action == "QUARANTINE":
                st.error(f"🛑 QUARANTINED: ML classified transfer as ATTACK. Decryption aborted.")
                
            with st.expander("Detailed Pipeline Audit"):
                st.json(res)

with tab2:
    st.header("Network Attack Simulation")
    st.write("Simulate a UDP Traffic Flood against the Flow Monitor:")
    flood_packets = st.slider("Flood Packets Count", 1000, 10000, 3000, step=1000)
    
    if st.button("Trigger UDP Flood"):
        res = st_lib.simulate_udp_flood(st.session_state.detector, n=flood_packets, size=44)
        ml = res["ml"]
        st.error(f"Verdict: {ml['tier']} (Attack Probability: {ml['attack_probability']:.4f})")
        st.write("Captured Flow Features:", res["features"])

with tab3:
    st.header("ML Performance & Model Metrics")
    m_col1, m_col2 = st.columns(2)
    with m_col1:
        st.image(str(ROOT / "ml" / "results" / "confusion_matrices.png"), caption="Confusion Matrices")
    with m_col2:
        st.image(str(ROOT / "ml" / "results" / "rf_feature_importance.png"), caption="Random Forest Feature Importance")
```

---

## 5. CONTROLLED SECURITY & ATTACK DEMONSTRATIONS (PART H & I)

When presenting to your professor or evaluator, Person 3 should run these 5 scenarios directly using `demo_ml_gate.py` or the Streamlit app:

```
┌────────────────────────────────┬───────────┬────────────┬───────────────────────┐
│ Scenario                       │ ML Tier   │ HMAC Valid │ System Action         │
├────────────────────────────────┼───────────┼────────────┼───────────────────────┤
│ 1. Legit Small File (4 KB)     │ NORMAL    │ True       │ ACCEPT                │
│ 2. Legit Large File (2 MB)     │ SUSPICIOUS│ True       │ ACCEPT_WITH_WARNING   │
│ 3. Tampered Ciphertext         │ NORMAL    │ False      │ REJECT_TAMPERED       │
│ 4. Impostor Key (Eve)          │ NORMAL    │ False      │ REJECT_TAMPERED       │
│ 5. UDP Flood (3000 pkts)       │ ATTACK    │ N/A        │ QUARANTINE            │
└────────────────────────────────┴───────────┴────────────┴───────────────────────┘
```

### Key Distinction to Explain in Viva/Presentation:
> *"HMAC-SHA512 guarantees cryptographic payload integrity (detecting bit-flips or wrong keys), whereas the Random Forest ML gate monitors overall network flow behavior (detecting traffic floods and volumetric anomalies)."*

---

## 6. END-TO-END & PERFORMANCE BENCHMARKING (PART J & K)

To collect experimental timing metrics for your report table, run the following command in PowerShell:

```powershell
$env:PYTHONPATH="application;ml;crypto"
python application/demo_ml_gate.py --size 1048576 --gap 0.0005
```

This generates `ml/results/app_demo_results.csv` containing actual packet rates, throughputs, probabilities, and execution decisions.

---

## 7. SYSTEM ARCHITECTURE & CALL-FLOW DIAGRAMS (PART L)

Use this diagram in your PPT (Slide 2) and Final Report:

```
  Client (Alice)                        Server / Receiver (Bob)
   --------------                        ----------------------
 1. Encrypt file & derive HMAC  ------> 2. Receive whole network flow
    (ECDH -> HKDF -> AES-CTR               (FlowMonitor captures spkts,
     + HMAC-SHA512)                        sbytes, rate, sinpkt, etc.)
                                                   │
                                        3. ML Classification Gate
                                           (IDSDetector.classify)
                                                   │
                                        ┌──────────┴──────────┐
                                        │                     │
                                    [ATTACK]       [NORMAL / SUSPICIOUS]
                                        │                     │
                                 4a. QUARANTINE        4b. HMAC Verification
                                  (Never decrypt,          (verify_hmac)
                                   no file write)             │
                                                     ┌────────┴────────┐
                                                     │                 │
                                                 [FAILED]           [PASSED]
                                                     │                 │
                                              5a. REJECT          5b. AES Decrypt &
                                                  (Tampered /         Write File
                                                   Wrong Key)         (out_path)
```

---

## 8. PPT SLIDES & FINAL REPORT ASSEMBLY (PART M, N, O)

### PPT Slide Ownership & Coordination

| Slide # | Title | Primary Owner | Person 3 Responsibility |
| :---: | :--- | :--- | :--- |
| **Slide 1** | Title & Problem Statement | Person 3 | Create clean introductory layout & objectives. |
| **Slide 2** | System Architecture | Person 3 | Insert call-flow diagram & component interaction. |
| **Slide 3** | Key Exchange (ECDH P-256) | Person 1 | Format math equations & key size visuals. |
| **Slide 4** | Encryption & HMAC (AES-CTR) | Person 1 | Format AES-256-CTR & HMAC-SHA512 visuals. |
| **Slide 5** | ML Dataset (UNSW-NB15) | Person 2 | Insert feature distribution charts. |
| **Slide 6** | ML Pipeline & Model Training | Person 2 | Insert Random Forest metrics & CV scores. |
| **Slide 7** | Application & Wire Protocol | Person 3 | Show `Package` wire format & socket stream design. |
| **Slide 8** | Controlled Attack Demos | Person 3 | Show screenshots of Tamper Rejection & UDP Flood Quarantine. |
| **Slide 9** | Performance Benchmarks | Person 3 | Insert execution timing table (`app_demo_results.csv`). |
| **Slide 10** | Conclusion & Security Summary| Person 3 | Highlight dual-layer defense summary. |

---

## 9. PERSON 3 TIMELINE & CHECKLIST

- [x] **Day 1 (Architecture)**: Review `application/secure_transfer.py` and `demo_ml_gate.py`.
- [x] **Day 2 (Crypto Integration)**: Verify `crypto/test_crypto.py` runs from repo root.
- [x] **Day 3 (ML Model Load)**: Verify `ml/models/ids_pipeline.joblib` loads cleanly (compressed size 38.26 MB).
- [ ] **Day 4 (UI Creation)**: Build `application/app.py` using Streamlit.
- [ ] **Day 5 (Testing & Benchmarking)**: Run `demo_ml_gate.py` and capture screenshots of all 5 attack scenarios.
- [ ] **Day 6 (PPT & Report)**: Assemble the final presentation slides and integrate Person 1 & 2's writeups into the final report.

---
*Generated by QA & Release Engineering Audit for Person 3 Handoff.*
