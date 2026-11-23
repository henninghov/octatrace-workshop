import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/factory_credential_lookup.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'factory_fixtures.dart' as fixture;

final keyBytes = <int>[4, ...List<int>.filled(64, 2)];
final key = keyBytes.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
final keyHash = sha256.convert(keyBytes).toString();
final credentialHash = sha256.convert([1, 2, 3]).toString();

class Gateway implements FactoryGateway {
  String state = 'ready', role = 'Link', publicHash = keyHash;
  int fetches = 0;
  @override
  Future<Json> factoryStatus(String deviceId) async => {
    ...fixture.status(state, role: role),
    'public_key_sha256': publicHash,
    'credential_sha256': state == 'ready' ? credentialHash : null,
  };
  @override
  Future<PublicFactoryCredential> publicCredential({
    required String deviceId,
    required String role,
    required String expectedDigest,
  }) async {
    fetches++;
    return PublicFactoryCredential.fromJson(
      {
        'v': 1,
        'device_id': deviceId,
        'role': role,
        'credential': '010203',
        'credential_sha256': credentialHash,
      },
      deviceId: deviceId,
      role: role,
      expectedDigest: expectedDigest,
    );
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('retrieval binds the recorded key and original issuance digest for both roles', () async {
    for (final role in ['Link', 'Core']) {
      final gateway = Gateway()..role = role;
      final credential = await FactoryCredentialLookup(gateway)
          .find(fixture.unit(role: role), fixture.article(role), key);
      expect(credential.bytes, [1, 2, 3]);
      expect(credential.digest, credentialHash);
      expect(gateway.fetches, 1);
    }
  });
  test(
    'pending, mismatched key, role and invalid input stop before retrieval',
    () async {
      for (final gateway in [
        Gateway()..state = 'pending',
        Gateway()..publicHash = 'ee' * 32,
        Gateway()..role = 'Core',
      ]) {
        await expectLater(
          FactoryCredentialLookup(gateway)
              .find(fixture.unit(), fixture.article(), key),
          throwsFormatException,
        );
        expect(gateway.fetches, 0);
      }
      final gateway = Gateway();
      await expectLater(
        FactoryCredentialLookup(gateway)
            .find(fixture.unit(), fixture.article(), 'bad'),
        throwsFormatException,
      );
      expect(gateway.fetches, 0);
    },
  );
}
