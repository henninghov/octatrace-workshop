import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from flutter_sdk import find_flutter_sdk


class FlutterSdkTest(unittest.TestCase):
    def test_explicit_sdk_and_path_discovery(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as temp:
            root = Path(temp) / 'sdk with spaces'
            bin_dir = root / 'bin'
            bin_dir.mkdir(parents=True)
            for name in ('flutter', 'dart'):
                file = bin_dir / name
                file.write_text('#!/bin/sh\nexit 0\n')
                file.chmod(0o755)
            self.assertEqual(find_flutter_sdk({'FLUTTER_SDK': str(root), 'PATH': ''}), root)
            self.assertEqual(find_flutter_sdk({'PATH': str(bin_dir)}), root)
            link_dir = Path(temp) / 'links'
            link_dir.mkdir()
            (link_dir / 'flutter').symlink_to(bin_dir / 'flutter')
            self.assertEqual(find_flutter_sdk({'PATH': str(link_dir)}), root)

    def test_missing_or_incomplete_sdk_fails_with_actionable_error(self):
        with self.assertRaisesRegex(ValueError, 'Set FLUTTER_SDK'):
            find_flutter_sdk({'PATH': ''})
        with self.assertRaisesRegex(ValueError, 'missing an executable'):
            find_flutter_sdk({'FLUTTER_SDK': str(ROOT / 'missing-sdk'), 'PATH': ''})

    def test_explicit_invalid_sdk_does_not_fall_back_to_path(self):
        with self.assertRaisesRegex(ValueError, 'missing an executable'):
            find_flutter_sdk({'FLUTTER_SDK': str(ROOT / 'missing-sdk'), 'PATH': os.environ.get('PATH', '')})


if __name__ == '__main__':
    unittest.main()
