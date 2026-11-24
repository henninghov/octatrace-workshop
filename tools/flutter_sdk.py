#!/usr/bin/env python3
"""Locate the Flutter SDK without assuming a particular developer's machine."""

import os
from pathlib import Path
import shutil
import sys


def find_flutter_sdk(environ=None):
    environ = os.environ if environ is None else environ
    configured = environ.get('FLUTTER_SDK')
    if configured:
        root = Path(configured).expanduser().resolve()
    else:
        executable = shutil.which('flutter', path=environ.get('PATH', ''))
        if not executable:
            raise ValueError('Set FLUTTER_SDK or put the pinned Flutter SDK on PATH')
        root = Path(executable).resolve().parent.parent
    for name in ('flutter', 'dart'):
        path = root / 'bin' / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f'Flutter SDK is missing an executable bin/{name}: {root}')
    return root


if __name__ == '__main__':
    try:
        print(find_flutter_sdk())
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
