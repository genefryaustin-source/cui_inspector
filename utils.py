from datetime import datetime
import hashlib

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))
