"""Load locally pinned consumer tests without an owner checkout."""
import hashlib
import json
from pathlib import Path

_EXPECTED = {'inspection_suite.py': '4da7384590b3b9fc26b897ce74d24ddbf9b8136fa8d8533489924b6fa20d4384', 'delivery_common.py': '5d31693fb0c75e57854480c38765b9ba661fc11605fe154649f60e992ff4b9d8', 'pins_suite.py': 'c8e9861c1f18a8b5d354b64f29fc0a02b64eeb6aa3bf539422a64e8d09092004'}
_ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'consumer-contract-tests.lock.json').is_file())
_LOCK = _ROOT / 'consumer-contract-tests.lock.json'
_SUITES = Path(__file__).parent / 'consumer_contract_suites'

def load(name, namespace):
    if name not in _EXPECTED or _LOCK.is_symlink() or _SUITES.is_symlink():
        raise RuntimeError('Consumer test pin mismatch')
    suite = _SUITES / name
    if suite.is_symlink():
        raise RuntimeError('Consumer test pin mismatch')
    lock = json.loads(_LOCK.read_text())
    if (type(lock.get('format')) is not int or lock.get('format') != 1
            or lock.get('source_repository') != 'octatrace-firmware' or lock.get('files') != _EXPECTED):
        raise RuntimeError('Consumer test pin mismatch')
    source = suite.read_bytes()
    if hashlib.sha256(source).hexdigest() != _EXPECTED[name]:
        raise RuntimeError('Consumer test pin mismatch')
    exec(compile(source, str(suite), 'exec'), namespace)
