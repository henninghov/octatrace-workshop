import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_identity_key.dart';
import 'package:octatrace_workshop/domain/registry.dart';

final class LookupGateway implements WorkshopGateway {
  LookupGateway(this.registry);
  final Registry registry;
  @override
  Future<Registry> load() async => registry;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  final deviceData = <String, dynamic>{
    'id': 'device',
    'serial': 'D123456789012',
    'article_revision_id': 'revision',
    'provisioning_state': 'provisioned',
    'owner_user_id': null,
    'firmware_version': null,
    'hardware_uid': '11' * 8,
  };
  final device = DeviceRecord.fromJson(deviceData);
  final article = ArticleRevision.fromJson({
    'id': 'revision',
    'article_id': 'article',
    'code': 'x',
    'name': 'x',
    'role': 'Link',
    'revision': 1,
    'case_version': '1',
    'parts': <Object>[],
  });
  Json event(String key) {
    Json frame(String boot) => {
      'state': 'ready',
      'device_id': device.id,
      'serial': device.serial,
      'article_id': article.articleId,
      'article_revision_id': article.id,
      'hardware': device.hardwareUid,
      'role': article.role,
      'boot': boot,
      'public_key': key,
    };
    final bytes = [
      for (var i = 0; i < key.length; i += 2)
        int.parse(key.substring(i, i + 2), radix: 16),
    ];
    return {
      'event_type': 'provisioned',
      'device_id': device.id,
      'report': {
        'algorithm': 'P256-SHA256',
        'public_key_sha256': sha256.convert(bytes).toString(),
        'verification': {'before': frame('aa' * 16), 'after': frame('bb' * 16)},
      },
    };
  }

  Registry registry(List<Json> runs, {List<Json>? devices}) =>
      Registry.fromJson({
        'articles': <Object>[],
        'devices': devices ?? [deviceData],
        'runs': runs,
      });
  final key = '04${'22' * 64}';
  test('accepts the server-verified key and rejects an ambiguous history', () {
    expect(
      provisionedKey(registry([event(key), event(key)]), device, article),
      key,
    );
    expect(
      () => provisionedKey(
        registry([event(key), event('04${'33' * 64}')]),
        device,
        article,
      ),
      throwsFormatException,
    );
  });
  test('key lookup reads the current authenticated registry', () async {
    final lookup = IdentityKeyLookup(LookupGateway(registry([event(key)])));
    expect(await lookup.find(device, article), key);
  });
  test('requires valid, device-bound, before-and-after evidence', () {
    final corrupt = event(key);
    (corrupt['report'] as Json)['public_key_sha256'] = '00' * 32;
    final mismatch = event(key);
    (((mismatch['report'] as Json)['verification'] as Json)['after']
            as Json)['hardware'] =
        '22' * 8;
    for (final rows in [
      <Json>[],
      [corrupt],
      [mismatch],
    ]) {
      expect(
        () => provisionedKey(registry(rows), device, article),
        throwsFormatException,
      );
    }
  });
  test('fresh registry identity must still be present and provisioned', () {
    for (final rows in [
      <Json>[],
      [deviceData, deviceData],
      [
        {...deviceData, 'provisioning_state': 'retired'},
      ],
      [
        {...deviceData, 'serial': 'D123456789013'},
      ],
      [
        {...deviceData, 'article_revision_id': 'other'},
      ],
      [
        {...deviceData, 'hardware_uid': '22' * 8},
      ],
      [
        {...deviceData, 'owner_user_id': 'another-owner'},
      ],
    ]) {
      expect(
        () => provisionedKey(
          registry([event(key)], devices: rows),
          device,
          article,
        ),
        throwsFormatException,
      );
    }
  });
}
