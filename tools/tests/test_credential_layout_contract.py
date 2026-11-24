"""Run the pinned firmware-owned suite against this repository."""
import hashlib
import json
from pathlib import Path

_root = next(p for p in Path(__file__).resolve().parents if (p / 'shared-contract-tests.lock.json').is_file())
_lock_path = _root / 'shared-contract-tests.lock.json'
_suite = Path(__file__).parent / 'shared_contract_suites' / 'test_credential_layout_contract.py'
_expected = '6b2931234d84ba3e6e6f90b74205249eb8c7e04df00d6e1d2f1161ae8d6e0f89'
if _lock_path.is_symlink() or _suite.parent.is_symlink() or _suite.is_symlink():
    raise RuntimeError('Shared contract test pin mismatch: test_credential_layout_contract')
_lock = json.loads(_lock_path.read_text())
_source = _suite.read_bytes()
if (type(_lock.get('format')) is not int or _lock.get('format') != 1
        or _lock.get('source_repository') != 'octatrace-firmware'
        or _lock.get('files', {}).get('test_credential_layout_contract.py') != _expected
        or hashlib.sha256(_source).hexdigest() != _expected):
    raise RuntimeError('Shared contract test pin mismatch: test_credential_layout_contract')
exec(compile(_source, str(_suite), 'exec'), globals())
