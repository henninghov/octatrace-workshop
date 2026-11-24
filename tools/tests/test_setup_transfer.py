"""Run the pinned firmware-owned suite against this repository."""
import hashlib
import json
from pathlib import Path

_root = next(p for p in Path(__file__).resolve().parents if (p / 'shared-contract-tests.lock.json').is_file())
_lock_path = _root / 'shared-contract-tests.lock.json'
_suite = Path(__file__).parent / 'shared_contract_suites' / 'test_setup_transfer.py'
_expected = '5ed6144f57bc7c3d2b218ba62df9dbfd8b2511a4c3c233e946a8f2ccf1ae813c'
if _lock_path.is_symlink() or _suite.parent.is_symlink() or _suite.is_symlink():
    raise RuntimeError('Shared contract test pin mismatch: test_setup_transfer')
_lock = json.loads(_lock_path.read_text())
_source = _suite.read_bytes()
if (type(_lock.get('format')) is not int or _lock.get('format') != 1
        or _lock.get('source_repository') != 'octatrace-firmware'
        or _lock.get('files', {}).get('test_setup_transfer.py') != _expected
        or hashlib.sha256(_source).hexdigest() != _expected):
    raise RuntimeError('Shared contract test pin mismatch: test_setup_transfer')
exec(compile(_source, str(_suite), 'exec'), globals())
