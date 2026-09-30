"""
ml/test_ml_layer.py  -  integration tests: ML layer + teammate's real crypto.
    python ml/test_ml_layer.py
Gate-logic tests use a stub detector (deterministic); plumbing tests use the real IDSDetector.
"""
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "application"))
import secure_transfer as st                                   # noqa: E402
from key_exchange import generate_key_pair                     # noqa: E402
from ids_detector import IDSDetector, FlowMonitor, FEATURES    # noqa: E402

PASSED = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    PASSED.append(bool(cond))
    if not cond:
        raise SystemExit(f"test failed: {name}")


class StubDetector:                                            # fixed verdict, real interface
    def __init__(self, tier): self.tier = tier
    def classify(self, feats):
        return {"tier": self.tier, "attack_probability": 0.0, "thresholds": {},
                "out_of_range_features": [], "features": feats}


def make_flow(pkg):
    m = FlowMonitor("tcp")
    for i in range(0, len(pkg.ciphertext), st.TCP_SEGMENT):
        m.record_src(min(st.TCP_SEGMENT, len(pkg.ciphertext) - i), ts=i * 1e-5)
    m.close(True)
    return m


def setup(size=5000):
    a_priv, a_pub = generate_key_pair()
    b_priv, b_pub = generate_key_pair()
    td = Path(tempfile.mkdtemp())
    data = os.urandom(size)
    (td / "in.bin").write_bytes(data)
    pkg = st.prepare_package(td / "in.bin", a_priv, b_pub, td / "pkg")
    return a_priv, a_pub, b_priv, b_pub, td, data, pkg


# 1. package on disk has the teammate's layout and lengths
a_priv, a_pub, b_priv, b_pub, td, data, pkg = setup()
check("package files written (ciphertext/nonce/hmac)", all((td / "pkg" / f).exists() for f in
      ("ciphertext.bin", "nonce.bin", "hmac.bin")))
check("nonce=16B, hmac=64B, ciphertext length == plaintext length",
      len(pkg.nonce) == 16 and len(pkg.hmac) == 64 and len(pkg.ciphertext) == len(data))
check("wire format round-trips", st.Package.from_wire(pkg.to_wire()) == pkg)

# 2. gate logic
mon = make_flow(pkg)
r = st.evaluate_and_decrypt(pkg, mon, StubDetector("NORMAL"), b_priv, a_pub, td / "o1.bin")
check("NORMAL + valid HMAC -> ACCEPT, file identical", r["action"] == "ACCEPT" and (td / "o1.bin").read_bytes() == data)

r = st.evaluate_and_decrypt(pkg, mon, StubDetector("SUSPICIOUS"), b_priv, a_pub, td / "o2.bin")
check("SUSPICIOUS + valid HMAC -> ACCEPT_WITH_WARNING", r["action"] == "ACCEPT_WITH_WARNING" and r["decrypted"])

r = st.evaluate_and_decrypt(pkg, mon, StubDetector("ATTACK"), b_priv, a_pub, td / "o3.bin")
check("ATTACK -> QUARANTINE, nothing decrypted/written",
      r["action"] == "QUARANTINE" and not r["decrypted"] and not (td / "o3.bin").exists())

bad = st.Package(pkg.nonce, pkg.hmac, bytes([pkg.ciphertext[0] ^ 1]) + pkg.ciphertext[1:])
r = st.evaluate_and_decrypt(bad, mon, StubDetector("NORMAL"), b_priv, a_pub, td / "o4.bin")
check("flipped ciphertext byte -> REJECT_TAMPERED (HMAC)", r["action"] == "REJECT_TAMPERED" and not r["decrypted"])

bad = st.Package(pkg.nonce, bytes([pkg.hmac[0] ^ 1]) + pkg.hmac[1:], pkg.ciphertext)
r = st.evaluate_and_decrypt(bad, mon, StubDetector("NORMAL"), b_priv, a_pub, td / "o5.bin")
check("flipped HMAC byte -> REJECT_TAMPERED", r["action"] == "REJECT_TAMPERED")

m_priv, m_pub = generate_key_pair()                            # impostor / wrong sender key
r = st.evaluate_and_decrypt(pkg, mon, StubDetector("NORMAL"), b_priv, m_pub, td / "o6.bin")
check("wrong sender public key -> REJECT_TAMPERED", r["action"] == "REJECT_TAMPERED" and not r["decrypted"])

r = st.evaluate_and_decrypt(pkg, mon, None, b_priv, a_pub, td / "o7.bin")
check("detector=None (HMAC-only baseline) still works", r["action"] == "ACCEPT")

# 3. feature schema really matches the model's expectation
f = mon.features()
check("FlowMonitor emits exactly the 14 trained feature names", set(f) == set(FEATURES))
check("all numeric features finite and >= 0",
      all(isinstance(f[c], (int, float)) and f[c] >= 0 for c in FEATURES if c not in ("proto", "state")))

# 4. real detector + real sockets end to end
det = IDSDetector()                                            # dummy or real model in ml/models/
v = det.classify(f)
check("IDSDetector returns tier + probability", v["tier"] in ("NORMAL", "SUSPICIOUS", "ATTACK") and 0 <= v["attack_probability"] <= 1)

class Force(StubDetector):                                     # real socket path, deterministic tier
    pass

holder, ready = {}, threading.Event()
t = threading.Thread(target=st.serve_once, args=(b_priv, a_pub, Force("NORMAL"), td / "sock_out.bin", holder, ready), daemon=True)
t.start(); ready.wait(5)
reply = st.send_wire("127.0.0.1", holder["port"], pkg.to_wire(), gap=0.0002)
t.join(10)
check("real TCP transfer: server decrypts, file identical", holder["result"]["decrypted"] and (td / "sock_out.bin").read_bytes() == data)
check("client receives server decision", reply.get("action") == "ACCEPT")

# tampered IN TRANSIT over a real socket
wire = bytearray(pkg.to_wire()); wire[-10] ^= 1
holder, ready = {}, threading.Event()
t = threading.Thread(target=st.serve_once, args=(b_priv, a_pub, Force("NORMAL"), td / "sock_out2.bin", holder, ready), daemon=True)
t.start(); ready.wait(5)
reply = st.send_wire("127.0.0.1", holder["port"], bytes(wire))
t.join(10)
check("tamper in transit over TCP -> rejected, no output file", reply["action"] == "REJECT_TAMPERED" and not (td / "sock_out2.bin").exists())

# junk stream (not our protocol) is profiled, not crashed
holder, ready = {}, threading.Event()
t = threading.Thread(target=st.serve_once, args=(b_priv, a_pub, Force("ATTACK"), td / "x.bin", holder, ready, "127.0.0.1", 0, 1.0), daemon=True)
t.start(); ready.wait(5)
reply = st.send_wire("127.0.0.1", holder["port"], os.urandom(20000))
t.join(10)
check("garbage TCP stream -> QUARANTINE (no crash)", reply["action"] == "QUARANTINE")

# 5. UDP flood produces attack-like features (exact packet boundaries)
res = st.simulate_udp_flood(None, n=2000, size=44)
uf = res["features"]
check("UDP flood: ~2000 tiny packets, no replies, very high rate",
      uf["spkts"] >= 1500 and uf["dpkts"] == 0 and uf["smean"] < 100 and uf["rate"] > 5000)

print(f"\nALL {len(PASSED)} CHECKS PASSED")
