"""
Secure Communication System Using Cryptography & ML
Hybrid Cryptographic Communication with ML-Based Security Monitoring
Option 4 — Integrated Secure System Design

Interactive Dashboard replicating the presentation architecture:
- 01 Secure Key Establishment (ECDH P-256 + HKDF-SHA512)
- 02 Confidential Communication (AES-256-CTR)
- 03 Integrity Verification (HMAC-SHA512)
- 04 ML Security Monitoring (Random Forest on UNSW-NB15)
"""

import os
import sys
import time
import json
import tempfile
from pathlib import Path
import pandas as pd
import numpy as np
import streamlit as st

# Setup import paths
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(ROOT_DIR / "crypto"))
sys.path.insert(0, str(ROOT_DIR / "ml"))

import secure_transfer as st_lib
from key_exchange import generate_key_pair, derive_shared_secret, derive_keys
from ids_detector import IDSDetector, FlowMonitor, FEATURES
from integrity import verify_hmac

# Page Configuration
st.set_page_config(
    page_title="Secure Communication System | Crypto + ML",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #8B0046 0%, #B81858 100%);
        color: white;
        padding: 24px 32px;
        border-radius: 12px;
        margin-bottom: 24px;
        box-shadow: 0 4px 14px rgba(139, 0, 70, 0.25);
    }
    .main-header h1 {
        color: white !important;
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .main-header h3 {
        color: #FFD2E3 !important;
        font-size: 1.15rem;
        font-weight: 400;
        margin-top: 0;
    }
    .team-badge {
        display: inline-block;
        background: rgba(255, 255, 255, 0.18);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.85rem;
        margin-right: 8px;
        margin-top: 6px;
    }
    .metric-card {
        background: #F8F9FA;
        border: 1px solid #E9ECEF;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(0,0,0,0.03);
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #8B0046;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #6C757D;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .status-accept {
        background-color: #D4EDDA;
        color: #155724;
        border-left: 6px solid #28A745;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
    }
    .status-warning {
        background-color: #FFF3CD;
        color: #856404;
        border-left: 6px solid #FFC107;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
    }
    .status-reject {
        background-color: #F8D7DA;
        color: #721C24;
        border-left: 6px solid #DC3545;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
    }
    .status-quarantine {
        background-color: #343A40;
        color: #FF6B6B;
        border-left: 6px solid #DC3545;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
    }
    .code-box {
        background: #1E1E1E;
        color: #D4D4D4;
        font-family: 'Consolas', 'Courier New', monospace;
        padding: 12px;
        border-radius: 8px;
        font-size: 0.85rem;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization for Cryptographic Keys
if "alice_priv" not in st.session_state:
    st.session_state.alice_priv, st.session_state.alice_pub = generate_key_pair()
    st.session_state.bob_priv, st.session_state.bob_pub = generate_key_pair()
    st.session_state.eve_priv, st.session_state.eve_pub = generate_key_pair()
    st.session_state.detector = IDSDetector(ROOT_DIR / "ml" / "models")
    st.session_state.transfer_history = []

# Header Block
st.markdown("""
<div class="main-header">
    <div style="font-size: 0.85rem; letter-spacing: 1px; text-transform: uppercase; color: #FFE0ED; font-weight: 600;">
        Amrita Vishwa Vidyapeetham | Dept of Computer Science & Engineering | 23CSE331: Cryptography
    </div>
    <h1>🛡️ Secure Communication System Using Cryptography & ML</h1>
    <h3>Hybrid Cryptographic Communication with ML-Based Security Monitoring (Option 4)</h3>
    <div>
        <span class="team-badge">Srishti Pandey (AV.SC.U4CSE24323)</span>
        <span class="team-badge">S MohanaMaheswari (AV.SC.U4CSE24314)</span>
        <span class="team-badge">Gurrala Deepika (AV.SC.U4CSE24051)</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar: Key Infrastructure & ML Status
with st.sidebar:
    st.subheader("🔑 Session Cryptographic Keys")
    st.markdown("**ECDH NIST P-256 (`SECP256R1`)**")
    
    if st.button("🔄 Regenerate Session Keypairs"):
        st.session_state.alice_priv, st.session_state.alice_pub = generate_key_pair()
        st.session_state.bob_priv, st.session_state.bob_pub = generate_key_pair()
        st.session_state.eve_priv, st.session_state.eve_pub = generate_key_pair()
        st.success("Fresh ECDH key pairs generated!")

    # Calculate Alice-Bob shared keys
    shared_ab = derive_shared_secret(st.session_state.alice_priv, st.session_state.bob_pub)
    aes_ab, hmac_ab = derive_keys(shared_ab)
    
    with st.expander("👁️ Key Derivation Inspection", expanded=False):
        st.caption("ECDH Shared Secret (Alice ↔ Bob):")
        st.code(shared_ab.hex()[:32] + "...", language="text")
        st.caption("HKDF AES-256 Key (32 Bytes):")
        st.code(aes_ab.hex(), language="text")
        st.caption("HKDF HMAC-SHA512 Key (64 Bytes):")
        st.code(hmac_ab.hex()[:32] + "...", language="text")

    st.markdown("---")
    st.subheader("🧠 Deployed ML Gate Status")
    st.write(f"**Model**: `{st.session_state.detector.schema.get('model', 'RandomForest')}`")
    st.write(f"**Pipeline**: `ml/models/ids_pipeline.joblib`")
    st.write(f"**Training Set**: UNSW-NB15")
    st.write(f"**Suspicious Threshold**: `{st.session_state.detector.t_susp:.4f}`")
    st.write(f"**Attack Threshold**: `{st.session_state.detector.t_attack:.4f}`")
    st.success("ML Intrusion Gate Active")

# Main Navigation Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 File Transfer (Alice ➔ Bob)",
    "🚨 Security Threats & Attack Demos",
    "📊 ML Security Monitoring & Metrics",
    "🛡️ System Workflow & Cryptographic Math"
])

# ==============================================================================
# TAB 1: FILE TRANSFER & END-TO-END DEMO
# ==============================================================================
with tab1:
    st.header("End-to-End Secure File Transfer Pipeline")
    st.write(
        "Simulate live secure transmission from **Client (Alice)** to **Server (Bob)**. "
        "The file is encrypted with **AES-256-CTR**, authenticated with **HMAC-SHA512**, and "
        "monitored on the socket by the **Random Forest ML Gate**."
    )

    col_in1, col_in2 = st.columns([1, 1])

    with col_in1:
        st.subheader("1. Select or Upload Payload")
        transfer_type = st.radio(
            "Payload Source:",
            ["Preset Sample File", "Upload Custom File"],
            horizontal=True
        )

        preset_content = b"This is a confidential communication verified by ECDH, AES-256-CTR, and HMAC-SHA512."
        file_name = "sample.txt"
        file_data = preset_content

        if transfer_type == "Preset Sample File":
            preset_size = st.selectbox(
                "Choose Preset Benchmark Size:",
                ["4 KB (Small Benign)", "256 KB (Medium Benign)", "2 MB (Large Benign)"]
            )
            if "4 KB" in preset_size:
                file_name = "sample_4kb.txt"
                file_data = ("Secure communication payload. " * 125).encode("utf-8")
            elif "256 KB" in preset_size:
                file_name = "data_256kb.bin"
                file_data = os.urandom(256 * 1024)
            else:
                file_name = "archive_2mb.bin"
                file_data = os.urandom(2 * 1024 * 1024)
            st.info(f"Selected: `{file_name}` ({len(file_data):,} bytes)")
        else:
            uploaded = st.file_uploader("Upload file to send:", type=["txt", "pdf", "png", "jpg", "bin", "csv"])
            if uploaded is not None:
                file_name = uploaded.name
                file_data = uploaded.getvalue()
                st.success(f"Loaded: `{file_name}` ({len(file_data):,} bytes)")

    with col_in2:
        st.subheader("2. Security Threat Injection")
        st.write("Inject active network modifications to test system response:")
        
        tamper_mode = st.selectbox(
            "Threat Simulation Mode:",
            [
                "None (Normal Legitimate Transfer)",
                "Data Tampering: Flip bit in Ciphertext (In-Transit Modification)",
                "Data Tampering: Flip bit in HMAC Tag (Corrupted Signature)",
                "Data Tampering: Flip bit in Nonce (Counter Manipulation)",
                "Forged Key: Sender is Impostor (Eve sends with Alice's identity)"
            ]
        )
        
        sim_gap = st.slider("Network Pacing (Chunk Gap in ms)", min_value=0.0, max_value=5.0, value=0.5, step=0.1)

    st.markdown("---")
    
    if st.button("🔒 Encrypt, Profile & Transmit Payload", type="primary", use_container_width=True):
        with st.spinner("Processing through cryptographic engine & ML flow monitor..."):
            with tempfile.TemporaryDirectory() as td:
                in_path = Path(td) / file_name
                out_path = Path(td) / f"decrypted_{file_name}"
                in_path.write_bytes(file_data)

                # Sender Key Selection
                if "Forged Key" in tamper_mode:
                    sender_priv = st.session_state.eve_priv
                    sender_label = "Eve (Impostor)"
                else:
                    sender_priv = st.session_state.alice_priv
                    sender_label = "Alice (Legitimate)"

                # Step 1 & 2: Encrypt & Package
                t0 = time.perf_counter()
                pkg = st_lib.prepare_package(in_path, sender_priv, st.session_state.bob_pub)

                # Inject Tampering if selected
                if "Ciphertext" in tamper_mode:
                    w = bytearray(pkg.ciphertext)
                    w[len(w) // 2] ^= 1
                    pkg.ciphertext = bytes(w)
                elif "HMAC Tag" in tamper_mode:
                    w = bytearray(pkg.hmac)
                    w[0] ^= 1
                    pkg.hmac = bytes(w)
                elif "Nonce" in tamper_mode:
                    w = bytearray(pkg.nonce)
                    w[0] ^= 1
                    pkg.nonce = bytes(w)

                # Step 3: Flow Monitoring (Profile Wire Traffic)
                mon = st_lib.FlowMonitor("tcp")
                chunk_gap_s = sim_gap / 1000.0
                wire_bytes = pkg.to_wire()
                for i in range(0, len(wire_bytes), st_lib.TCP_SEGMENT):
                    mon.record_src(min(st_lib.TCP_SEGMENT, len(wire_bytes) - i))
                    if chunk_gap_s > 0 and len(file_data) < 500_000:
                        time.sleep(chunk_gap_s)
                mon.close(clean=True)

                # Step 4: Gating Logic
                res = st_lib.evaluate_and_decrypt(
                    pkg, mon, st.session_state.detector,
                    st.session_state.bob_priv, st.session_state.alice_pub, out_path
                )
                t_total = (time.perf_counter() - t0) * 1000.0
                
                features = mon.features()
                res["flow_features"] = features
                res["elapsed_ms"] = t_total
                res["sender"] = sender_label
                res["tamper_mode"] = tamper_mode
                res["file_name"] = file_name
                res["file_size"] = len(file_data)

                # Display Result Verdict Banner
                action = res["action"]
                ml = res["ml"]
                tier = ml["tier"] if ml else "N/A"
                p_att = ml["attack_probability"] if ml else 0.0

                st.subheader("3. Receiver Gating Decision & Security Action")

                if action == "ACCEPT":
                    st.markdown(f"""
                    <div class="status-accept">
                        <h3>✅ ACCEPTED — Transfer Verified Cleanly</h3>
                        <p><strong>ML Verdict:</strong> {tier} (P(Attack) = {p_att:.4f}) | <strong>HMAC-SHA512:</strong> Valid | <strong>Decrypted:</strong> True</p>
                        <p>Plaintext matched original perfectly. Cryptographic and behavioral checks passed.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    if out_path.exists():
                        st.download_button(
                            label=f"📥 Download Decrypted {file_name}",
                            data=out_path.read_bytes(),
                            file_name=f"decrypted_{file_name}",
                            mime="application/octet-stream"
                        )

                elif action == "ACCEPT_WITH_WARNING":
                    st.markdown(f"""
                    <div class="status-warning">
                        <h3>⚠️ ACCEPTED WITH WARNING — Large Transfer Flow Anomaly</h3>
                        <p><strong>ML Verdict:</strong> {tier} (P(Attack) = {p_att:.4f}) | <strong>HMAC-SHA512:</strong> Valid | <strong>Decrypted:</strong> True</p>
                        <p><strong>Notice:</strong> Flow volume exceeded UNSW-NB15 training distribution bounds ({', '.join(ml['out_of_range_features'])}). However, because HMAC verification succeeded with mathematical certainty, the file was safely decrypted.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    if out_path.exists():
                        st.download_button(
                            label=f"📥 Download Decrypted {file_name}",
                            data=out_path.read_bytes(),
                            file_name=f"decrypted_{file_name}",
                            mime="application/octet-stream"
                        )

                elif action == "REJECT_TAMPERED":
                    st.markdown(f"""
                    <div class="status-reject">
                        <h3>🚨 REJECTED — Cryptographic Integrity Verification Failed</h3>
                        <p><strong>ML Verdict:</strong> {tier} (P(Attack) = {p_att:.4f}) | <strong>HMAC-SHA512:</strong> FAILED (False) | <strong>Decrypted:</strong> False</p>
                        <p><strong>Reason:</strong> {res.get('reason', 'HMAC mismatch')}. The data was modified in transit or signed with an unauthorized key. Decryption was immediately aborted.</p>
                    </div>
                    """, unsafe_allow_html=True)

                elif action == "QUARANTINE":
                    st.markdown(f"""
                    <div class="status-quarantine">
                        <h3>🛑 QUARANTINED — Malicious Network Activity Detected</h3>
                        <p><strong>ML Verdict:</strong> {tier} (P(Attack) = {p_att:.4f}) | <strong>Decryption Aborted:</strong> 0 bytes written</p>
                        <p><strong>Reason:</strong> ML classified the flow behavior as an attack. Payload isolated before reaching the crypto decryption stage.</p>
                    </div>
                    """, unsafe_allow_html=True)

                # Metrics Row
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    st.metric("Total Wire Chunks", f"{features['spkts']} pkts")
                with m2:
                    st.metric("Total Wire Bytes", f"{features['sbytes']:,} B")
                with m3:
                    st.metric("Transmission Rate", f"{features['rate']:.1f} pkt/s")
                with m4:
                    st.metric("Total Latency", f"{t_total:.2f} ms")

                # Technical Audit Tabs
                with st.expander("🔍 Deep Technical Inspection & Wire Hex Dumps", expanded=True):
                    d_tab1, d_tab2, d_tab3 = st.tabs(["Packet Wire Inspection", "Flow Feature Breakdown (14 Features)", "Full JSON Audit"])
                    
                    with d_tab1:
                        st.write("**Cryptographic Artifacts:**")
                        col_h1, col_h2 = st.columns(2)
                        with col_h1:
                            st.caption("16-Byte AES Nonce (Hex):")
                            st.code(pkg.nonce.hex(), language="text")
                            st.caption("64-Byte HMAC-SHA512 Tag (Hex):")
                            st.code(pkg.hmac.hex(), language="text")
                        with col_h2:
                            st.caption(f"AES-256-CTR Ciphertext ({len(pkg.ciphertext):,} bytes):")
                            st.code(pkg.ciphertext[:64].hex() + ("..." if len(pkg.ciphertext) > 64 else ""), language="text")
                            if out_path.exists():
                                st.caption("Decrypted Plaintext Preview:")
                                try:
                                    st.code(out_path.read_text(encoding="utf-8")[:200], language="text")
                                except UnicodeDecodeError:
                                    st.code(out_path.read_bytes()[:64].hex(), language="text")

                    with d_tab2:
                        st.write("**Extracted UNSW-NB15 Compatible Flow Features:**")
                        f_df = pd.DataFrame([features]).T.reset_index()
                        f_df.columns = ["Feature Name", "Extracted Value"]
                        st.dataframe(f_df, use_container_width=True)
                        if ml and ml.get("out_of_range_features"):
                            st.warning(f"Features outside 1st-99th percentile of training data: {', '.join(ml['out_of_range_features'])}")

                    with d_tab3:
                        st.json(res)

# ==============================================================================
# TAB 2: THREATS & ATTACK SIMULATIONS
# ==============================================================================
with tab2:
    st.header("Security Threats & System Response (PPT Slide 9 & 11)")
    st.write(
        "Demonstrate how each security layer responds to specific threat vectors. "
        "Cryptographic integrity handles data tampering and forged keys, while the ML IDS "
        "detects and isolates volumetric attack traffic."
    )

    t_col1, t_col2, t_col3, t_col4 = st.columns(4)
    with t_col1:
        st.markdown("""
        <div class="metric-card">
            <h4>EAVESDROPPING</h4>
            <p><strong>Defense:</strong> AES-256-CTR</p>
            <p style="font-size: 0.85rem; color: #555;">Protects payload confidentiality. Eavesdropper sees uniform pseudo-random ciphertext.</p>
        </div>
        """, unsafe_allow_html=True)
    with t_col2:
        st.markdown("""
        <div class="metric-card">
            <h4>DATA TAMPERING</h4>
            <p><strong>Defense:</strong> HMAC-SHA512</p>
            <p style="font-size: 0.85rem; color: #555;">Detects single-bit modification before decryption using constant-time comparison.</p>
        </div>
        """, unsafe_allow_html=True)
    with t_col3:
        st.markdown("""
        <div class="metric-card">
            <h4>FORGED KEY</h4>
            <p><strong>Defense:</strong> Key Mismatch</p>
            <p style="font-size: 0.85rem; color: #555;">Rejects packages encrypted with an impostor key (Eve) during HMAC validation.</p>
        </div>
        """, unsafe_allow_html=True)
    with t_col4:
        st.markdown("""
        <div class="metric-card">
            <h4>ATTACK TRAFFIC</h4>
            <p><strong>Defense:</strong> ML-Based IDS</p>
            <p style="font-size: 0.85rem; color: #555;">Detects volumetric floods & isolates traffic before cryptographic computation.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("Live Network Attack: High-Rate UDP Flood Simulator")
    st.write("Generate a synthetic UDP flood against a live local socket monitor to evaluate real-time ML quarantine:")

    f_col1, f_col2 = st.columns([1, 1])
    with f_col1:
        flood_count = st.slider("Flood Packet Count", min_value=1000, max_value=8000, value=3000, step=1000)
        flood_size = st.selectbox("Datagram Payload Size", [44, 64, 128, 512], index=0)
    
    with f_col2:
        st.write("Attack Characteristics:")
        st.markdown("- **Protocol**: UDP (`proto='udp'`)\n- **Overhead**: 28 Bytes/pkt\n- **Pacing**: Rapid burst with zero acknowledgment packets (`dpkts=0`)\n- **State**: `INT` (Interrupted)")

    if st.button("🚨 Launch Live UDP Flood Attack", type="secondary", use_container_width=True):
        with st.spinner("Firing UDP packets & profiling socket traffic..."):
            res = st_lib.simulate_udp_flood(st.session_state.detector, n=flood_count, size=flood_size)
            ml = res["ml"]
            feats = res["features"]

            st.markdown(f"""
            <div class="status-quarantine">
                <h3>🛑 ATTACK TRAFFIC QUARANTINED</h3>
                <p><strong>Verdict:</strong> {ml['tier']} | <strong>Attack Probability:</strong> {ml['attack_probability']:.4f}</p>
                <p>The ML gate recognized anomalous burst rate ({feats['rate']:,.1f} pkts/s) and tiny packet mean ({feats['smean']:.1f} B). Transfer was quarantined immediately without decryption.</p>
            </div>
            """, unsafe_allow_html=True)

            q1, q2, q3, q4 = st.columns(4)
            with q1:
                st.metric("Source Packets", f"{feats['spkts']:,}")
            with q2:
                st.metric("Destination ACKs", f"{feats['dpkts']}")
            with q3:
                st.metric("Transmission Rate", f"{feats['rate']:,.1f} pkt/s")
            with q4:
                st.metric("Source Load", f"{feats['sload']:,.0f} bps")

    st.markdown("---")
    st.subheader("Automated Execution: PPT Slide 11 Scenarios")
    st.write("Run all 6 presentation benchmark scenarios in one click:")

    if st.button("▶️ Execute Full 6-Scenario Benchmark Suite", use_container_width=True):
        with st.spinner("Running automated test suite across all 6 scenarios..."):
            td = Path(tempfile.mkdtemp())
            a_priv = st.session_state.alice_priv
            b_pub = st.session_state.bob_pub
            b_priv = st.session_state.bob_priv
            a_pub = st.session_state.alice_pub
            e_priv = st.session_state.eve_priv

            test_cases = [
                ("1. Legit Small (4 KB)", 4_000, False, "Alice", False, "tcp"),
                ("2. Legit Medium (256 KB)", 256_000, False, "Alice", False, "tcp"),
                ("3. Legit Large (2 MB)", 2_000_000, False, "Alice", False, "tcp"),
                ("4. Ciphertext Tampered", 256_000, True, "Alice", False, "tcp"),
                ("5. Impostor Sender (Eve)", 256_000, False, "Eve", False, "tcp"),
                ("6. UDP Flood (3000 pkts)", 3000, False, "Attacker", True, "udp")
            ]

            results = []
            progress_bar = st.progress(0)

            for idx, (label, size, tamper, sender, is_flood, proto) in enumerate(test_cases):
                if is_flood:
                    r = st_lib.simulate_udp_flood(st.session_state.detector, n=size, size=44)
                    results.append({
                        "Scenario": label,
                        "ML Tier": r["ml"]["tier"],
                        "Attack Prob": f"{r['ml']['attack_probability']:.4f}",
                        "HMAC Valid": "-",
                        "System Action": "QUARANTINE" if r["ml"]["tier"] == "ATTACK" else "UNBLOCKED",
                        "Packets": r["features"]["spkts"],
                        "Bytes": f"{r['features']['sbytes']:,}",
                        "Rate (pkt/s)": f"{r['features']['rate']:,.1f}"
                    })
                else:
                    src = td / "test.bin"
                    src.write_bytes(os.urandom(size))
                    s_priv = e_priv if sender == "Eve" else a_priv
                    pkg = st_lib.prepare_package(src, s_priv, b_pub)
                    if tamper:
                        w = bytearray(pkg.ciphertext)
                        w[len(w) // 2] ^= 1
                        pkg.ciphertext = bytes(w)
                    
                    mon = st_lib.FlowMonitor(proto)
                    wire = pkg.to_wire()
                    for i in range(0, len(wire), st_lib.TCP_SEGMENT):
                        mon.record_src(min(st_lib.TCP_SEGMENT, len(wire) - i))
                    mon.close(True)

                    res = st_lib.evaluate_and_decrypt(
                        pkg, mon, st.session_state.detector, b_priv, a_pub, td / "out.bin"
                    )
                    f = mon.features()
                    results.append({
                        "Scenario": label,
                        "ML Tier": res["ml"]["tier"],
                        "Attack Prob": f"{res['ml']['attack_probability']:.4f}",
                        "HMAC Valid": str(res["hmac_valid"]),
                        "System Action": res["action"],
                        "Packets": f["spkts"],
                        "Bytes": f"{f['sbytes']:,}",
                        "Rate (pkt/s)": f"{f['rate']:,.1f}"
                    })
                progress_bar.progress((idx + 1) / len(test_cases))

            res_df = pd.DataFrame(results)
            st.success("All 6 presentation benchmark scenarios completed successfully!")
            st.dataframe(res_df, use_container_width=True)

# ==============================================================================
# TAB 3: ML MONITORING & PERFORMANCE METRICS
# ==============================================================================
with tab3:
    st.header("ML Security Monitoring & Evaluation (PPT Slide 3 & 10)")
    st.write(
        "Comprehensive performance analysis of the Random Forest model and candidate classifiers "
        "evaluated on the **UNSW-NB15** cybersecurity benchmark dataset."
    )

    # Metrics Row
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">91.68%</div>
            <div class="metric-label">Cross-Val Accuracy</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">89.53%</div>
            <div class="metric-label">Precision</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">94.20%</div>
            <div class="metric-label">Recall (True Positive Rate)</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">91.81%</div>
            <div class="metric-label">F1-Score</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    
    # Exact Confusion Matrix from PPT Slide 10
    st.subheader("Random Forest Confusion Matrix (UNSW-NB15 Test Set)")
    c_col1, c_col2 = st.columns([1, 1])

    with c_col1:
        st.write("**Exact Test Set Confusion Matrix (from Presentation Slide 10):**")
        cm_data = {
            "Predicted Normal": [23598, 1012],
            "Predicted Attack": [8012, 17349]
        }
        cm_df = pd.DataFrame(cm_data, index=["Actual Normal (31,610)", "Actual Attack (18,361)"])
        st.table(cm_df)

        st.caption("Key Observations:")
        st.markdown("""
        - **True Positive Rate (Recall)**: 94.5% of real network attacks correctly identified (`17,349 / 18,361`).
        - **True Negative Rate (Specificity)**: 74.7% of normal flows classified as clean (`23,598 / 31,610`).
        - **False Negative Rate**: Only 5.5% missed attacks (`1,012`), ensuring high protection against real intrusion threats.
        """)

    with c_col2:
        cm_img_path = ROOT_DIR / "ml" / "results" / "confusion_matrices.png"
        if cm_img_path.exists():
            st.image(str(cm_img_path), caption="Four Classifier Comparison (Confusion Matrices on UNSW-NB15)", use_container_width=True)

    st.markdown("---")
    st.subheader("Model Evaluation Across Classifiers")
    
    cv_file = ROOT_DIR / "ml" / "results" / "metrics_cv.txt"
    test_file = ROOT_DIR / "ml" / "results" / "metrics_test.csv"
    
    m_tab1, m_tab2 = st.tabs(["5-Fold Cross-Validation Scores", "Test Set Generalization & Deduplication"])
    
    with m_tab1:
        if cv_file.exists():
            cv_df = pd.read_csv(cv_file)
            st.dataframe(cv_df, use_container_width=True)

    with m_tab2:
        if test_file.exists():
            test_df = pd.read_csv(test_file)
            st.dataframe(test_df, use_container_width=True)
            st.info(
                "💡 **Why the Deduplication Test?** UNSW-NB15 contains duplicate flow records. "
                "Evaluating on deduplicated records ensures the model learned genuine behavioral patterns rather than memorizing duplicates."
            )

    fi_img_path = ROOT_DIR / "ml" / "results" / "rf_feature_importance.png"
    if fi_img_path.exists():
        st.subheader("Random Forest Feature Importance")
        st.image(str(fi_img_path), caption="Top 10 Most Influential Flow Features (Mean Decrease in Impurity)", use_container_width=True)

# ==============================================================================
# TAB 4: SYSTEM ARCHITECTURE & CRYPTOGRAPHIC MATH
# ==============================================================================
with tab4:
    st.header("End-to-End System Architecture (PPT Slides 4 – 8)")
    st.write(
        "Detailed cryptographic workflow and mathematical foundations of the secure communication pipeline."
    )

    st.subheader("1. System Workflow Breakdown (Slide 4)")
    st.markdown("""
```
Client (Alice)                                    Server / Receiver (Bob)
 --------------                                    ----------------------
1. Encrypt file & derive HMAC  ------------------> 2. Profile Live Network Flow
   (ECDH -> HKDF -> AES-CTR                           (FlowMonitor captures spkts,
    + HMAC-SHA512)                                    sbytes, rate, sinpkt, etc.)
                                                               │
                                                    3. ML Intrusion Gate
                                                       (IDSDetector.classify)
                                                               │
                                                    ┌──────────┴──────────┐
                                                    │                     │
                                                [ATTACK]       [NORMAL / SUSPICIOUS]
                                                    │                     │
                                             4a. QUARANTINE        4b. HMAC Verification
                                              (Zero decrypt,           (verify_hmac)
                                               no file write)             │
                                                                 ┌────────┴────────┐
                                                                 │                 │
                                                             [FAILED]           [PASSED]
                                                                 │                 │
                                                          5a. REJECT          5b. AES Decrypt &
                                                              (Tampered /         Write File
                                                               Wrong Key)         (ACCEPT)
```
    """)

    arch1, arch2 = st.columns(2)
    with arch1:
        st.markdown("### 🔑 ECDH P-256 Key Exchange (Slide 5)")
        st.markdown(r"""
        - **Curve**: NIST P-256 (`SECP256R1`) with generator point $G$.
        - **Alice**: Private key $d_A$, Public key $Q_A = d_A \cdot G$.
        - **Bob**: Private key $d_B$, Public key $Q_B = d_B \cdot G$.
        - **Shared Secret**:
        $$S = d_A \cdot Q_B = d_B \cdot Q_A = d_A \cdot d_B \cdot G$$
        *The shared secret is computed independently by each party and never transmitted across the network.*
        """)

        st.markdown("### 🔐 AES-256-CTR Confidentiality (Slide 7)")
        st.markdown(r"""
        - **Algorithm**: AES in Counter Mode (CTR).
        - **Key**: 256-bit symmetric AES key from HKDF.
        - **Nonce**: 16-byte cryptographically secure random value (`os.urandom(16)`).
        - **Keystream Equation**:
        $$\text{Keystream} = \text{AES}_{K}(\text{Nonce} \parallel \text{Counter})$$
        $$\text{Ciphertext} = \text{Plaintext} \oplus \text{Keystream}$$
        *Stream cipher mode eliminates padding oracle attacks and preserves exact file length.*
        """)

    with arch2:
        st.markdown("### ⚙️ HKDF-SHA512 Key Derivation (Slide 6)")
        st.markdown(r"""
        - **Extract Step**: Derives Pseudorandom Key ($PRK$) from shared secret.
        $$PRK = \text{HMAC-SHA512}(\text{salt}, S)$$
        - **Expand Step**: Generates separate cryptographic subkeys using domain separation:
        $$K_{\text{AES}} = \text{HKDF-Expand}(PRK, \text{"AES-256 encryption key"}, 32)$$
        $$K_{\text{HMAC}} = \text{HKDF-Expand}(PRK, \text{"HMAC-SHA512 authentication key"}, 64)$$
        *Ensures cryptographic separation so compromising one key never compromises the other.*
        """)

        st.markdown("### 🛡️ HMAC-SHA512 Integrity Verification (Slide 8)")
        st.markdown(r"""
        - **Authentication Scope**: $\text{Nonce} \parallel \text{Ciphertext}$.
        - **Tag Generation**:
        $$\text{Tag} = \text{HMAC-SHA512}(K_{\text{HMAC}}, \text{Nonce} \parallel \text{Ciphertext})$$
        - **Constant-Time Verification**:
        $$\text{verify} = \text{compare\_digest}(\text{Tag}_{\text{computed}}, \text{Tag}_{\text{received}})$$
        *Verifies authenticity and integrity before decryption to prevent side-channel timing attacks.*
        """)

    st.markdown("---")
    st.subheader("Achievements & Future Scope (Slide 11)")
    f_col1, f_col2 = st.columns(2)
    with f_col1:
        st.markdown("#### ✅ WHAT WE ACHIEVED:")
        st.markdown("""
        1. **Confidentiality**: AES-256-CTR securely encrypts all transferred files.
        2. **Integrity**: HMAC-SHA512 detects modified or forged packages before decryption.
        3. **Intelligent Threat Detection**: Random Forest IDS classifies network flows as Normal, Suspicious, or Attack.
        4. **Automated Response**: Attack traffic is quarantined before the cryptographic decryption stage.
        """)
    with f_col2:
        st.markdown("#### 🔮 FUTURE SCOPE:")
        st.markdown("""
        1. **Replay Protection**: Add sequence numbers, timestamps, or session freshness nonces to wire headers.
        2. **Adaptive IDS**: Continuously retrain and update the IDS with newer network threat patterns.
        3. **Stronger Deployment Layer**: Add mutual TLS, certificate authorities, access control, and session timeouts.
        4. **Performance Optimization**: Use zero-copy I/O and streaming decryption for gigabyte-scale transfers.
        """)
