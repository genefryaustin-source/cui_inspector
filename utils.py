from datetime import datetime
import hashlib


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def sha256_bytes(data: bytes):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def clamp(n, lo, hi):
    return max(lo, min(hi, n))

