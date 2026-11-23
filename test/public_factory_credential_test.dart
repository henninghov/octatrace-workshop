import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';

const device = '99000000-0000-4000-8000-000000000001';
String digest(List<int> bytes) => sha256.convert(bytes).toString();
String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
Json response(List<int> bytes, {String role = 'Link'}) => {
  'v': 1,
  'device_id': device,
  'role': role,
  'credential': hex(bytes),
  'credential_sha256': digest(bytes),
};
PublicFactoryCredential parse(
  Json data, {
  String role = 'Link',
  String? expected,
}) => PublicFactoryCredential.fromJson(
  data,
  deviceId: device,
  role: role,
  expectedDigest: expected ?? digest([1, 2, 3]),
);

void main() {
  test(
    'selected LINK and CORE receive immutable exact bytes at the maximum bound',
    () {
      for (final role in ['Link', 'Core']) {
        final bytes = List<int>.generate(271, (i) => i % 256);
        final value = parse(
          response(bytes, role: role),
          role: role,
          expected: digest(bytes),
        );
        expect(value.bytes, bytes);
        expect(value.digest, digest(bytes));
        expect(value.toString(), '[Public factory credential]');
        expect(() => value.bytes[0] = 42, throwsUnsupportedError);
      }
    },
  );
  test('malformed responses and mismatched device, role or original digest fail closed', () {
    final good = response([1, 2, 3]);
    for (final bad in <Json>[
      {...good, 'extra': 'private'},
      {...good}..remove('role'),
      {...good, 'v': 2},
      {...good, 'device_id': '99000000-0000-4000-8000-000000000002'},
      {...good, 'role': 'Core'},
      {...good, 'credential_sha256': '1' * 64},
      {...good, 'credential': null},
      {...good, 'credential': ''},
      {...good, 'credential': 'A1'},
      {...good, 'credential': '123'},
      {...good, 'credential': 'x1'},
      {...good, 'credential': '01' * 272},
      {...good, 'credential': '010204'},
    ]) {
      expect(() => parse(bad), throwsFormatException);
    }
    expect(() => parse(good, role: 'bad'), throwsFormatException);
    expect(() => parse(good, expected: '0' * 64), throwsFormatException);
    expect(
      () => PublicFactoryCredential.fromJson(
        good,
        deviceId: 'bad',
        role: 'Link',
        expectedDigest: digest([1, 2, 3]),
      ),
      throwsFormatException,
    );
  });
}
