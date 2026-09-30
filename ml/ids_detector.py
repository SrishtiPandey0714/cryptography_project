"""
ml/ids_detector.py  -  ML layer of the secure-communication project.

Two classes:
  FlowMonitor  - turns the traffic of ONE connection into the same 12 numeric +
                 2 categorical features the model was trained on (UNSW-NB15 style).
  IDSDetector  - loads the trained sklearn pipeline and returns a 3-tier verdict.

IMPORTANT (be honest about this in the report):
  * The payload is encrypted, so the detector only ever sees flow METADATA
    (sizes, counts, timing, protocol). Crypto hides content, ML watches behaviour.
  * We have no packet capture, so a TCP "packet" is approximated by one recv() chunk
    (<= 1448 bytes) and TCP ACKs are emulated (1 per 2 segments). UDP is exact
    because datagram boundaries are preserved. Upgrade path: scapy/pcap capture.
"""
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

NUM = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
       "sload", "dload", "sinpkt", "dinpkt", "smean", "dmean"]
CAT = ["proto", "state"]
FEATURES = NUM + CAT

# UNSW-NB15 (Argus) counts bytes on the wire, i.e. including IP+transport headers.
# TCP with timestamps option: 20 (IP) + 32 (TCP) = 52.   UDP: 20 + 8 = 28.
HEADER_OVERHEAD = {"tcp": 52, "udp": 28}
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent / "models"


class FlowMonitor:
    """Records one flow. src = connection initiator (client / Alice)."""

    def __init__(self, proto="tcp", emulate_tcp_acks=None):
        self.proto = proto
        self.overhead = HEADER_OVERHEAD[proto]
        self.emulate_tcp_acks = (proto == "tcp") if emulate_tcp_acks is None else emulate_tcp_acks
        self._src, self._dst = [], []          # lists of (timestamp, wire_bytes)
        self.clean = True

    def record_src(self, payload_len, ts=None):
        self._src.append((time.perf_counter() if ts is None else ts, payload_len + self.overhead))

    def record_dst(self, payload_len, ts=None):
        self._dst.append((time.perf_counter() if ts is None else ts, payload_len + self.overhead))

    def close(self, clean=True):
        self.clean = clean

    @staticmethod
    def _mean_gap_ms(ts):
        ts = sorted(ts)
        return float(np.mean(np.diff(ts)) * 1000.0) if len(ts) > 1 else 0.0

    def features(self):
        src, dst = list(self._src), list(self._dst)
        if not src and not dst:
            raise ValueError("empty flow - nothing was recorded")
        if self.emulate_tcp_acks:                       # delayed-ACK: one ACK per 2 segments
            dst += [(src[i][0], self.overhead) for i in range(1, len(src), 2)]
        stamps = [t for t, _ in src + dst]
        span = max(stamps) - min(stamps)
        dur = span if span >= 1e-6 else 0.0             # single-burst flow: dur 0 => rate/load 0
        sp, dp = len(src), len(dst)
        sb, db = sum(b for _, b in src), sum(b for _, b in dst)
        per_s = (lambda x: x / dur) if dur > 0 else (lambda x: 0.0)
        return {
            "dur": dur, "spkts": sp, "dpkts": dp, "sbytes": sb, "dbytes": db,
            "rate": float(min(per_s(max(sp + dp - 1, 0)), 1e6)),   # UNSW caps rate at 1e6
            "sload": per_s(sb * 8.0), "dload": per_s(db * 8.0),    # bits per second
            "sinpkt": self._mean_gap_ms([t for t, _ in src]),     # ms
            "dinpkt": self._mean_gap_ms([t for t, _ in dst]),
            "smean": sb / sp if sp else 0.0, "dmean": db / dp if dp else 0.0,
            "proto": self.proto,
            "state": "FIN" if (self.proto == "tcp" and self.clean) else "INT",
        }


class IDSDetector:
    """Loads models/ids_pipeline.joblib + models/feature_schema.json (from Kaggle)."""

    def __init__(self, model_dir=DEFAULT_MODEL_DIR):
        model_dir = Path(model_dir)
        self.model = joblib.load(model_dir / "ids_pipeline.joblib")
        self.schema = json.loads((model_dir / "feature_schema.json").read_text())
        self.cols = self.schema["numeric"] + self.schema["categorical"]
        self.t_susp = float(self.schema.get("t_suspicious", 0.5))
        self.t_attack = float(self.schema.get("t_attack", 0.5))
        self.ranges = self.schema.get("train_ranges", {})
        self.is_dummy = bool(self.schema.get("dummy", False))
        if self.is_dummy:
            warnings.warn("IDSDetector is using the DUMMY plumbing model - its verdicts are meaningless.")
        try:
            import sklearn
            saved = self.schema.get("sklearn_version")
            if saved and saved != sklearn.__version__:
                warnings.warn(f"model trained with scikit-learn {saved}, you run {sklearn.__version__}")
        except Exception:
            pass

    def out_of_range(self, feats):
        """Numeric features outside the 1st-99th percentile of the training data.
        This is the quickest way to see WHY a real app flow looks 'foreign' to the model."""
        out = []
        for c in self.schema["numeric"]:
            r = self.ranges.get(c)
            if r and not (r[0] <= feats[c] <= r[1]):
                out.append(c)
        return out

    def classify(self, feats):
        p = float(self.model.predict_proba(pd.DataFrame([feats])[self.cols])[0, 1])
        tier = "ATTACK" if p >= self.t_attack else "SUSPICIOUS" if p >= self.t_susp else "NORMAL"
        return {"tier": tier, "attack_probability": round(p, 4),
                "thresholds": {"suspicious": self.t_susp, "attack": self.t_attack},
                "out_of_range_features": self.out_of_range(feats), "features": feats}
