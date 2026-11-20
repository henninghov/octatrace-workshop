"""Serial substitute for the local Workshop integration test. Never open USB."""
from contextlib import contextmanager
import os
from pathlib import Path
import sys
from unittest.mock import patch

root = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(root / 'tools'), str(root / 'tests')]
import provision
import provision_platform
from test_bench import Port
from test_provision import FRAME

def inventory():
    return [{'mode': 'app', 'label': 'Synthetic bench port', 'hardware': FRAME['hardware']}]

@contextmanager
def open_port(hardware, source, role):
    assert hardware == FRAME['hardware']
    frame = dict(FRAME, id=1, build=source, role=role, signature='', challenge='')
    port = Port(raw=b'}\n') if os.environ['BENCH_CASE'] == 'malformed' else Port([frame])
    try:
        yield provision.ProvisionClient(port, hardware, source, clock=port.clock, role=role)
    finally:
        assert port.sent == b'P1 1 info\n', 'Unexpected USB traffic'

args = sys.argv[2:]
if args[0] not in ('inventory', 'identity'):
    raise ValueError('Only discovery and readback are supported in this fixture')
with patch.object(provision_platform, 'inventory', inventory), \
     patch.object(provision_platform, 'catalogue', return_value=[]), \
     patch.object(provision_platform, 'open_client', open_port):
    sys.exit(provision.main(args))
