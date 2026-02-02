import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPO_DIR = DATA_DIR / "repo"
OBJ_DIR = REPO_DIR / "objects"

def _ensure():
    OBJ_DIR.mkdir(parents=True, exist_ok=True)

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _path_for(sha: str) -> Path:
    return OBJ_DIR / sha[:2] / sha

def write_object(data: bytes):
    _ensure()
    sha = sha256_bytes(data)
    p = _path_for(sha)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_bytes(data)
    rel = p.relative_to(REPO_DIR).as_posix()
    return sha, rel, len(data)

def read_object(relpath: str) -> bytes:
    return (REPO_DIR / relpath).read_bytes()

def verify_object(relpath: str, expected_sha: str):
    try:
        data = read_object(relpath)
    except Exception:
        return False, None
    actual = sha256_bytes(data)
    return actual == expected_sha, actual
