"""
application/secure_transfer.py  -  glue between the crypto layer and the ML layer.

Uses the teammate's crypto files UNCHANGED (crypto/key_exchange.py, encryption.py,
integrity.py, decryption.py) and produces the same 3-file package
(ciphertext.bin, nonce.bin, hmac.bin).

Receiver pipeline (this is the architecture in the report):
    receive whole transfer  ->  ML flow classification  ->  HMAC verification  ->  decrypt
        ATTACK      : quarantine, never decrypt
        SUSPICIOUS  : warn, but still gated by HMAC
        NORMAL      : proceed
    HMAC failure    : reject (tampered / wrong key), never decrypt

Person 3 (UI) can call `evaluate_and_decrypt()` directly from Flask/Streamlit, or use the
socket helpers below.
"""
import json
import socket
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("crypto", "ml"):                       # crypto modules use flat imports
    sys.path.insert(0, str(ROOT / sub))

from key_exchange import derive_shared_secret, derive_keys          # noqa: E402
from encryption import encrypt_file                                  # noqa: E402
from integrity import generate_hmac, verify_hmac                     # noqa: E402
from decryption import decrypt_data                                  # noqa: E402
from ids_detector import FlowMonitor                                 # noqa: E402

MAGIC = b"SFT1"
HEADER_FMT = ">4sBHQ"                              # magic, nonce_len, hmac_len, ciphertext_len
HEADER_SIZE = struct.calcsize(HEADER_FMT)
TCP_SEGMENT = 1448                                 # typical MSS payload; 1 recv() ~ 1 "packet"
MAX_CIPHERTEXT = 512 * 1024 * 1024


@dataclass
class Package:
    nonce: bytes
    hmac: bytes
    ciphertext: bytes

    def to_wire(self):
        head = struct.pack(HEADER_FMT, MAGIC, len(self.nonce), len(self.hmac), len(self.ciphertext))
        return head + self.nonce + self.hmac + self.ciphertext

    @staticmethod
    def from_wire(buf):
        magic, nl, hl, cl = struct.unpack(HEADER_FMT, buf[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("bad magic")
        o = HEADER_SIZE
        return Package(buf[o:o + nl], buf[o + nl:o + nl + hl], buf[o + nl + hl:o + nl + hl + cl])

    @staticmethod
    def from_dir(d):
        d = Path(d)
        return Package((d / "nonce.bin").read_bytes(), (d / "hmac.bin").read_bytes(),
                       (d / "ciphertext.bin").read_bytes())


# ---------------------------------------------------------------- sender side
def prepare_package(input_file, sender_private, receiver_public, out_dir=None):
    """ECDH -> HKDF-SHA512 -> AES-256-CTR -> HMAC-SHA512 over (nonce + ciphertext).
    If out_dir is given, also writes ciphertext.bin / nonce.bin / hmac.bin there."""
    aes_key, hmac_key = derive_keys(derive_shared_secret(sender_private, receiver_public))
    with tempfile.TemporaryDirectory() as td:
        ct_path = Path(td) / "ciphertext.bin"
        nonce = encrypt_file(str(input_file), str(ct_path), aes_key)   # teammate's function
        ct = ct_path.read_bytes()
    pkg = Package(nonce, generate_hmac(nonce + ct, hmac_key), ct)
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "ciphertext.bin").write_bytes(pkg.ciphertext)
        (out / "nonce.bin").write_bytes(pkg.nonce)
        (out / "hmac.bin").write_bytes(pkg.hmac)
    return pkg


def send_wire(host, port, wire, chunk=TCP_SEGMENT, gap=0.0, timeout=30):
    """Send a package over TCP. `gap` (seconds) between chunks mimics real network pacing."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(0, len(wire), chunk):
            s.sendall(wire[i:i + chunk])
            if gap:
                time.sleep(gap)
        s.shutdown(socket.SHUT_WR)
        reply = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            reply += part
    return json.loads(reply.decode()) if reply else {}


# -------------------------------------------------------------- receiver side
def evaluate_and_decrypt(package, monitor, detector, receiver_private, sender_public, out_path):
    """The gating logic. `detector=None` disables the ML gate (HMAC-only baseline)."""
    result = {"ml": None, "hmac_valid": None, "decrypted": False, "output_path": None}
    _, hmac_key = derive_keys(derive_shared_secret(receiver_private, sender_public))

    if detector is not None:
        result["ml"] = detector.classify(monitor.features())
    tier = result["ml"]["tier"] if result["ml"] else "NORMAL"

    result["hmac_valid"] = verify_hmac(package.nonce + package.ciphertext, package.hmac, hmac_key)

    if tier == "ATTACK":
        result["action"] = "QUARANTINE"
        result["reason"] = "ML flagged the flow as an attack; transfer was not decrypted."
        return result
    if not result["hmac_valid"]:
        result["action"] = "REJECT_TAMPERED"
        result["reason"] = "HMAC-SHA512 verification failed (modified data or wrong key)."
        return result

    aes_key, _ = derive_keys(derive_shared_secret(receiver_private, sender_public))
    try:
        plaintext = decrypt_data(package.ciphertext, package.nonce, package.hmac, aes_key, hmac_key)
    except ValueError as e:                          # teammate's decrypt_data re-verifies the HMAC
        result["action"], result["reason"] = "REJECT_TAMPERED", str(e)
        return result
    Path(out_path).write_bytes(plaintext)
    result.update(decrypted=True, output_path=str(out_path),
                  action="ACCEPT" if tier == "NORMAL" else "ACCEPT_WITH_WARNING",
                  reason="ok" if tier == "NORMAL" else "ML tier SUSPICIOUS; HMAC valid, file accepted.")
    return result


def _receive_flow(conn, monitor, idle_timeout=3.0, max_bytes=MAX_CIPHERTEXT + 1024):
    """Read one connection to the end, recording every recv() chunk in the FlowMonitor."""
    buf, expected, header_ok = bytearray(), None, True
    conn.settimeout(idle_timeout)
    complete = False
    while True:
        try:
            chunk = conn.recv(TCP_SEGMENT)
        except socket.timeout:
            break
        if not chunk:
            break
        monitor.record_src(len(chunk))
        buf += chunk
        if expected is None and header_ok and len(buf) >= HEADER_SIZE:
            magic, nl, hl, cl = struct.unpack(HEADER_FMT, bytes(buf[:HEADER_SIZE]))
            if magic != MAGIC or cl > MAX_CIPHERTEXT:
                header_ok = False                   # not our protocol: keep draining to profile it
            else:
                expected = HEADER_SIZE + nl + hl + cl
        if expected is not None and len(buf) >= expected:
            complete = True
            break
        if len(buf) > max_bytes:
            break
    monitor.close(clean=complete)
    return bytes(buf), header_ok, complete


def handle_connection(conn, receiver_private, sender_public, detector, out_path, idle_timeout=3.0):
    monitor = FlowMonitor("tcp")
    raw, header_ok, complete = _receive_flow(conn, monitor, idle_timeout)
    if header_ok and complete:
        result = evaluate_and_decrypt(Package.from_wire(raw), monitor, detector,
                                      receiver_private, sender_public, out_path)
    else:                                            # garbage / truncated stream
        ml = detector.classify(monitor.features()) if (detector and monitor._src) else None
        result = {"ml": ml, "hmac_valid": None, "decrypted": False, "output_path": None,
                  "action": "QUARANTINE" if (ml and ml["tier"] == "ATTACK") else "REJECT_BAD_PROTOCOL",
                  "reason": "stream did not follow the transfer protocol"}
    result["flow_features"] = monitor.features() if monitor._src else None
    try:
        brief = {k: result[k] for k in ("action", "hmac_valid", "reason")}
        brief["tier"] = result["ml"]["tier"] if result["ml"] else None
        conn.sendall(json.dumps(brief).encode())
    except OSError:
        pass
    return result


def serve_once(receiver_private, sender_public, detector, out_path, holder, ready,
               host="127.0.0.1", port=0, idle_timeout=3.0):
    """Accept ONE connection (used by tests / collector). holder['port'] gets the bound port."""
    with socket.socket() as srv:
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(20)
        holder["port"] = srv.getsockname()[1]
        ready.set()
        conn, _ = srv.accept()
        with conn:
            holder["result"] = handle_connection(conn, receiver_private, sender_public,
                                                 detector, out_path, idle_timeout)


def serve_forever(receiver_private, sender_public, detector, out_dir, stop_event,
                  host="0.0.0.0", port=5001, on_result=None):
    """Long-running server for the real app. `on_result(result)` feeds the dashboard."""
    n = 0
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        srv.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                n += 1
                res = handle_connection(conn, receiver_private, sender_public, detector,
                                        Path(out_dir) / f"received_{n}.bin")
            if on_result:
                on_result(res)


# ---------------------------------------------------------- attack simulation
def udp_monitor(holder, ready, host="127.0.0.1", first_wait=5.0, idle=0.5, max_packets=500000):
    """Profile an incoming UDP flow. Datagram boundaries are real, so features are exact."""
    mon = FlowMonitor("udp")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.bind((host, 0))
        holder["port"] = s.getsockname()[1]
        ready.set()
        s.settimeout(first_wait)
        while len(mon._src) < max_packets:
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            mon.record_src(len(data))
            s.settimeout(idle)
    holder["monitor"] = mon


def udp_flood(host, port, n=3000, size=44, gap=0.0):
    """Suspicious-traffic simulator for the demo button: many tiny datagrams, no replies."""
    payload = b"\x00" * size
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(n):
            s.sendto(payload, (host, port))
            if gap:
                time.sleep(gap)


def simulate_udp_flood(detector, n=3000, size=44, gap=0.0):
    """Run a flood against a local monitor and classify it. Returns the detector verdict."""
    holder, ready = {}, threading.Event()
    t = threading.Thread(target=udp_monitor, args=(holder, ready), daemon=True)
    t.start()
    ready.wait(5)
    udp_flood("127.0.0.1", holder["port"], n, size, gap)
    t.join(10)
    feats = holder["monitor"].features()
    return {"features": feats, "ml": detector.classify(feats) if detector else None}
