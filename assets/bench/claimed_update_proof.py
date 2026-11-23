"""Authenticated read-only proof for an operator-supervised firmware update.

This adapter reuses the firmware owner's P1 client and signature verification.
It neither installs firmware nor modifies a device's identity or ownership.
"""
import json
import secrets
import subprocess
import sys
from pathlib import Path


def read_proof(selection, connect, verify, token_hex=secrets.token_hex):
    """Bind a fresh proof to the selected identity, build and current boot."""
    challenge = token_hex(32)
    attempt = dict(selection, challenge=challenge)
    with connect(selection['hardware'], selection['source'], role=selection['role']) as client:
        before = client.info()
        if before['state'] != 'ready' or before['busy'] or before['failed']:
            raise ValueError('Device identity is not ready for update')
        proof = client.prove(challenge)
        verify(proof, attempt)
        if proof['boot'] != before['boot']:
            raise ValueError('Device restarted during identity proof')
        return proof


def main():
    root = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(root / 'tools'))
    from provision import unique_object, verify
    from provision_platform import open_client
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('Identity proof input exceeds limit')
    selection = json.loads(raw, object_pairs_hook=unique_object)
    proof = read_proof(selection, open_client, verify)
    print(json.dumps({'proof': proof}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('Update identity proof stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)
