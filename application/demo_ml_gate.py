"""
application/demo_ml_gate.py  -  runs the full secure-transfer pipeline on YOUR crypto files with
the trained detector and prints a results table (paste it into the report / show it in the viva).

    python application/demo_ml_gate.py                       # uses ml/models/
    python application/demo_ml_gate.py --model-dir ml/models --size 262144 --gap 0.001

Scenarios: legitimate transfers, tampering in transit, impostor key, UDP flood, garbage TCP.
"""
import argparse
import csv
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secure_transfer as st                                   # noqa: E402
from key_exchange import generate_key_pair                     # noqa: E402
from ids_detector import IDSDetector                           # noqa: E402


def tcp_transfer(detector, wire, b_priv, a_pub, gap, td, name):
    holder, ready = {}, threading.Event()
    t = threading.Thread(target=st.serve_once, daemon=True,
                         args=(b_priv, a_pub, detector, td / f"{name}.out", holder, ready, "127.0.0.1", 0, 2.0))
    t.start()
    ready.wait(5)
    st.send_wire("127.0.0.1", holder["port"], wire, gap=gap)
    t.join(30)
    return holder["result"]


def row(scenario, r):
    ml = r.get("ml") or {}
    f = r.get("flow_features") or {}
    return {"scenario": scenario, "ml_tier": ml.get("tier", "-"), "p_attack": ml.get("attack_probability", "-"),
            "hmac_valid": r.get("hmac_valid"), "action": r["action"],
            "spkts": f.get("spkts"), "sbytes": f.get("sbytes"), "rate": round(f["rate"], 1) if f else None,
            "out_of_range": ",".join(ml.get("out_of_range_features", []))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=str(ROOT / "ml" / "models"))
    ap.add_argument("--size", type=int, default=262_144)
    ap.add_argument("--gap", type=float, default=0.001)
    args = ap.parse_args()

    det = IDSDetector(args.model_dir)
    print(f"Detector: {det.schema['model']}  thresholds: suspicious>={det.t_susp:.3f}  attack>={det.t_attack:.3f}"
          + ("   *** DUMMY MODEL - results meaningless ***" if det.is_dummy else ""))

    a_priv, a_pub = generate_key_pair()
    b_priv, b_pub = generate_key_pair()
    m_priv, m_pub = generate_key_pair()
    td = Path(tempfile.mkdtemp())
    rows = []

    for label, size, gap in [("legit file, small (4 KB)", 4_000, args.gap),
                             (f"legit file ({args.size // 1024} KB)", args.size, args.gap),
                             ("legit file, large (2 MB)", 2_000_000, 0.0002)]:
        src = td / "in.bin"
        src.write_bytes(os.urandom(size))
        pkg = st.prepare_package(src, a_priv, b_pub)
        rows.append(row(label, tcp_transfer(det, pkg.to_wire(), b_priv, a_pub, gap, td, "legit")))

    src = td / "in.bin"
    src.write_bytes(os.urandom(args.size))
    pkg = st.prepare_package(src, a_priv, b_pub)
    w = bytearray(pkg.to_wire())
    w[len(w) // 2] ^= 1
    rows.append(row("ciphertext tampered in transit", tcp_transfer(det, bytes(w), b_priv, a_pub, args.gap, td, "tamper")))

    pkg_bad = st.prepare_package(src, m_priv, b_pub)           # impostor signs with own keys
    rows.append(row("impostor sender (wrong key)", tcp_transfer(det, pkg_bad.to_wire(), b_priv, a_pub, args.gap, td, "imp")))

    for n, sz in [(3000, 44), (8000, 64)]:
        res = st.simulate_udp_flood(det, n=n, size=sz)
        ml = res["ml"]
        rows.append({"scenario": f"UDP flood {n} x {sz}B", "ml_tier": ml["tier"], "p_attack": ml["attack_probability"],
                     "hmac_valid": "-", "action": "QUARANTINE" if ml["tier"] == "ATTACK" else "not blocked",
                     "spkts": res["features"]["spkts"], "sbytes": res["features"]["sbytes"],
                     "rate": round(res["features"]["rate"], 1), "out_of_range": ",".join(ml["out_of_range_features"])})

    rows.append(row("garbage TCP stream", tcp_transfer(det, os.urandom(30_000), b_priv, a_pub, 0.0005, td, "junk")))

    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("\n" + "  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))
    out = ROOT / "ml" / "results"
    out.mkdir(exist_ok=True)
    with open(out / "app_demo_results.csv", "w", newline="") as fh:
        wtr = csv.DictWriter(fh, fieldnames=cols)
        wtr.writeheader()
        wtr.writerows(rows)
    print("\nsaved ->", out / "app_demo_results.csv")


if __name__ == "__main__":
    main()
