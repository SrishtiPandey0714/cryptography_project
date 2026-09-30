"""
ml/collect_app_flows.py  -  record REAL flows produced by YOUR crypto layer.

Runs genuine ECDH -> HKDF -> AES-CTR -> HMAC transfers (teammate's code) over real loopback
TCP sockets, for many file sizes and network pacings, and stores each flow's features.

  ml/data/app_flows_normal.csv       label=0  -> used to RETRAIN (Kaggle cell 2) if the
                                                 model calls your legitimate transfers attacks
  ml/data/app_flows_attack_demo.csv  label=1  -> UDP-flood simulations, DEMO/EVALUATION only,
                                                 never used for training

    python ml/collect_app_flows.py --repeats 3
"""
import argparse
import csv
import os
import random
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "application"))
import secure_transfer as st                                          # noqa: E402
from key_exchange import generate_key_pair                            # noqa: E402
from ids_detector import FEATURES                                     # noqa: E402

SIZES = [1_000, 4_000, 16_000, 64_000, 256_000, 1_000_000, 4_000_000]   # bytes (bucket = group)
GAPS = [0.0, 0.0002, 0.001, 0.005]                                       # seconds between chunks


def one_transfer(size, gap):
    a_priv, a_pub = generate_key_pair()
    b_priv, b_pub = generate_key_pair()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = td / "in.bin"
        payload = os.urandom(size)
        src.write_bytes(payload)
        pkg = st.prepare_package(src, a_priv, b_pub)
        holder, ready = {}, threading.Event()
        t = threading.Thread(target=st.serve_once, daemon=True,
                             args=(b_priv, a_pub, None, td / "out.bin", holder, ready))
        t.start()
        ready.wait(5)
        st.send_wire("127.0.0.1", holder["port"], pkg.to_wire(), gap=gap)
        t.join(30)
        res = holder["result"]
        assert res["decrypted"] and (td / "out.bin").read_bytes() == payload, "round-trip failed!"
        return res["flow_features"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out-dir", default=str(ROOT / "ml" / "data"))
    ap.add_argument("--skip-attacks", action="store_true")
    args = ap.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    random.seed(1)

    cols = FEATURES + ["label", "source", "group", "size_bytes", "gap_s"]
    rows = []
    for size in SIZES:
        for gap in GAPS:
            if size >= 1_000_000 and gap >= 0.005:          # keeps total runtime reasonable
                continue
            for _ in range(args.repeats):
                actual = int(size * random.uniform(0.75, 1.25))
                f = one_transfer(actual, gap)
                rows.append({**f, "label": 0, "source": "app", "group": size,
                             "size_bytes": actual, "gap_s": gap})
            print(f"collected size~{size:>9,} gap={gap}s  ({len(rows)} flows so far)")
    with open(out / "app_flows_normal.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} legitimate flows -> {out / 'app_flows_normal.csv'}")

    if not args.skip_attacks:
        att = []
        for n, sz in [(2000, 44), (5000, 64), (1500, 512), (8000, 44)]:
            r = st.simulate_udp_flood(None, n=n, size=sz)
            att.append({**r["features"], "label": 1, "source": "sim_udp_flood",
                        "group": f"udp{n}x{sz}", "size_bytes": n * sz, "gap_s": 0.0})
        with open(out / "app_flows_attack_demo.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(att)
        print(f"Wrote {len(att)} simulated attack flows -> {out / 'app_flows_attack_demo.csv'}")


if __name__ == "__main__":
    main()
