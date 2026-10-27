#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
workshop_sdk="${FLUTTER_SDK:-/Users/henninghov/Sites/sdk/flutter}"
mkdir -p build coverage
"$workshop_sdk/bin/flutter" --version --machine > build/flutter-version.json
python3 -B - <<'PY'
import json
from pathlib import Path
v=json.loads(Path('build/flutter-version.json').read_text())
assert v['frameworkVersion']=='3.47.6' and v['dartSdkVersion'].split()[0]=='3.13.5', 'Pinned Flutter/Dart toolchain required'
for name in ['lcov.info','default.info','configured.info','result.json']:
 Path('coverage',name).unlink(missing_ok=True)
PY
"$workshop_sdk/bin/dart" format --output=none --set-exit-if-changed lib test
"$workshop_sdk/bin/flutter" analyze --no-pub --fatal-infos
"$workshop_sdk/bin/flutter" test --no-pub --coverage --timeout=30s
cp coverage/lcov.info coverage/default.info
# Synthetic config constructs/disposes real SDK adapters; no login/network/USB.
"$workshop_sdk/bin/flutter" test --no-pub --coverage --timeout=30s test/bootstrap_test.dart \
 --dart-define=SUPABASE_URL=https://example.invalid \
 --dart-define=SUPABASE_PUBLISHABLE_KEY=synthetic-publishable \
 --dart-define=WORKSHOP_FIRMWARE_ROOT=/nonexistent
cp coverage/lcov.info coverage/configured.info
python3 -B tools/check_coverage.py coverage/default.info coverage/configured.info
