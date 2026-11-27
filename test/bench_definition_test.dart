import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/provisioning_runner.dart';

import 'provisioning_test.dart' as usb;
import 'widget_test.dart' as fixtures;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late BenchDefinition definition;
  late String snapshot;
  setUp(() async {
    snapshot = await rootBundle.loadString(BenchDefinition.asset);
    definition = BenchDefinition.fromSnapshot(snapshot);
  });

  test(
    'restart revisions preserve legacy snapshots and pin qualified builds',
    () async {
      for (final name in [
        'credential-readiness',
        'credential-installation',
        'credential-intent-stop',
        'credential-preparation',
      ]) {
        final old = BenchDefinition.fromSnapshot(
          await rootBundle.loadString('assets/bench/$name.v1.json'),
        );
        final current = BenchDefinition.fromSnapshot(
          await rootBundle.loadString('assets/bench/$name.v2.json'),
        );
        expect(old.guide['revision'], 1);
        expect(current.guide['revision'], 2);
        expect(current.guide['key'], old.guide['key']);
        expect(current.guide['steps'][4]['evaluation'], 'automatic');
        expect(current.builds.map((b) => b.source).toSet(), {
          '44313723afe279f590d2bd235b1c9e6a200d82a537b720e9a1ca2d296c588706',
        });
        expect(
          current.builds.first.artifact,
          'd87b0bba1341e53a3ddf99d6865f5948a2e2d2415b8a60be32b03536bf290243',
        );
        expect(
          current.builds.last.artifact,
          'dbac837b40efb1748f5268a92316f9eb717d85075af2737ba836ac499c646c4a',
        );
        expect(
          () => BenchDefinition.fromSnapshot('${current.snapshot} '),
          throwsFormatException,
        );
      }
    },
  );

  ProvisionedIdentityRead admit(
    BenchBuild build, {
    Json device = const {},
    Json article = const {},
    Json target = const {},
    BenchDefinition? guide,
  }) {
    return (guide ?? definition).admit(
      device: DeviceRecord.fromJson({
        'id': fixtures.device,
        'serial': 'D000000000123',
        'article_revision_id': fixtures.revision,
        'provisioning_state': 'provisioned',
        'hardware_uid': usb.hardware,
        'owner_user_id': build.role == 'Core' ? fixtures.other : null,
        ...device,
      }),
      article: ArticleRevision.fromJson({
        'id': fixtures.revision,
        'article_id': fixtures.other,
        'code': 'TEST',
        'name': 'Board',
        'role': build.role,
        'revision': 1,
        'case_version': 'A',
        'parts': [],
        ...article,
      }),
      target: UsbTarget.fromJson({...usb.targetJson(), ...target}),
      build: build,
    );
  }

  for (final recovery in [false, true]) {
    test('paired runner binds proofs, resources and retirement, recovery=$recovery', () async {
      final guide = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(
          recovery
              ? BenchDefinition.recoveryAsset
              : BenchDefinition.pairedAsset,
        ),
      );
      final root = await Directory.systemTemp.createTemp('pair-contract-');
      addTearDown(() => root.delete(recursive: true));
      for (final name in [
        'usb-provisioning.lock.json',
        'control-storage.lock.json',
      ]) {
        await File('vendor/$name').copy('${root.path}/$name');
      }
      final pins = {
        ...ProcessProvisioningRunner.pins,
        ...ProcessProvisioningRunner.controlPins,
        ...guide.runnerFiles,
      };
      final peers = {
        for (final build in guide.builds)
          build.role: (
            read: admit(
              build,
              guide: guide,
              device: {
                'hardware_uid': build.role == 'Link'
                    ? usb.hardware
                    : '1234567800000002',
              },
              target: {
                'hardware': build.role == 'Link'
                    ? usb.hardware
                    : '1234567800000002',
              },
            ),
            publicKey: '04${'11' * 64}',
          ),
      };
      const attempt = 'a4000000-0000-4000-8456-000000000001';
      final procedure = recovery
          ? 'c83-temporary-recovery.v1'
          : 'c83-permanent-peer-handshake.v1';
      List<Json> records() {
        final list = <Json>[
          {
            'start': {
              'attempt': attempt,
              'definition': procedure,
              'carrier': 'supervised_usb',
              'identity': recovery ? 'temporary_test' : 'provisioned_permanent',
              'pair_sha256': guide.guide['pair_sha256'],
            },
          },
        ];
        var order = 0;
        for (final entry in peers.entries) {
          final role = entry.key, read = entry.value.read;
          final ident = {
            'role': role,
            'hardware': read.device.hardwareUid,
            'boot': '22' * 16,
            'build': read.build.source,
          };
          final proof = {
            ...ident,
            'state': 'ready',
            'busy': false,
            'failed': false,
            'device_id': read.device.id,
            'serial': read.device.serial,
            'article_id': read.article.articleId,
            'article_revision_id': read.article.id,
            'public_key': entry.value.publicKey,
            'signature': '44' * 64,
          };
          final sample = {
            ...ident,
            'generation': 1,
            'accepted': true,
            'busy': false,
            'ticket': 0,
          };
          final begin = list.length;
          list.addAll([
            {
              'role': role,
              'before_proof': {
                ...proof,
                'challenge': (++order).toString() * 64,
              },
            },
            {
              'role': role,
              'operation': 'done',
              'status': {...sample, 'state': 'confirmed'},
            },
            {
              'role': role,
              'resources': {
                ...ident,
                'type': 'c83_resources',
                'generation': 1,
                'heap_fault': false,
              },
            },
            {
              'role': role,
              'operation': 'cancel',
              'status': {...sample, 'state': 'cancelled'},
            },
            {
              'role': role,
              'after_proof': {...proof, 'challenge': (++order).toString() * 64},
            },
            {
              'role': role,
              'handshake': 'confirmed',
              'attempt': attempt,
              'definition': procedure,
              'generation': 1,
              'source': read.build.source,
              'artifact': read.build.artifact,
            },
          ]);
          if (recovery) {
            final digest = benchHash('synthetic public events');
            final encoded = base64Encode(
              zlib.encode(utf8.encode('synthetic public events')),
            );
            final finalProofs = list.sublist(begin + 4);
            list.removeRange(begin + 1, list.length);
            final labels = [
              'entropy',
              'deadline',
              'continuity',
              for (final r in ['Link', 'Core']) ...[
                '$r-cancel-stale',
                '$r-slots',
                '$r-signing',
              ],
            ];
            Json memory(int gen) => {
              ...ident,
              'type': 'c83_resources',
              'generation': gen,
              'heap_fault': false,
              'usb_free': 2200,
              'worker_free': 4096,
              'radio_reads': 4,
              'flash_reads': 4,
            };
            Json status(int gen) => {
              ...ident,
              'generation': gen,
              'state': 'cancelled',
              'ticket': 0,
              'fault': 0,
              'accepted': true,
              'busy': false,
              'cleaned': true,
              'temporary': true,
            };
            var gen = 1;
            for (final label in labels) {
              final own = label.startsWith('$role-');
              final shared = [
                'entropy',
                'deadline',
                'continuity',
              ].contains(label);
              final name = shared
                  ? label
                  : label.substring(label.indexOf('-') + 1);
              if (own || shared) {
                final cancel = name == 'cancel-stale';
                final sample = {
                  ...status(gen),
                  'state': cancel ? 'cancelled' : 'failed',
                  'accepted': cancel,
                  'fault': cancel
                      ? 0
                      : ({
                          'entropy': 1,
                          'slots': 2,
                          'signing': 3,
                          'deadline': 4,
                          'continuity': 5,
                        }[name]),
                };
                list.add({
                  'role': role,
                  'case': cancel ? 'cancel' : name,
                  'generation': gen,
                  'status': sample,
                  'resources': memory(gen),
                  if (cancel) 'borrowed_ticket': 7,
                });
                if (cancel) {
                  list.add({
                    'role': role,
                    'case': 'stale',
                    'generation': gen + 1,
                    'old_generation': gen,
                    'old_ticket': 7,
                    'status': {
                      ...status(gen + 1),
                      'state': 'active',
                      'ticket': 8,
                    },
                  });
                }
              }
              gen++;
              list.add({
                'role': role,
                'recovered_after': label,
                'attempt':
                    'a4000000-0000-4000-8456-${gen.toString().padLeft(12, '0')}',
                'generation': gen,
                'flights': [1, 2, 3, 4, 5, 6, 7, 8],
                'retirement': status(gen),
                'radio_cooldown_refused': {...status(gen), 'state': 'active'},
                'resources': memory(gen),
                'observations_sha256': digest,
              });
              gen++;
            }
            list.add({
              'role': role,
              'trace': {
                'encoding': 'zlib-base64-ndjson',
                'bytes': 23,
                'content': encoded,
                'sha256': digest,
              },
            });
            list.add({'role': role, 'resources': memory(gen - 1)});
            finalProofs.last['generation'] = gen - 1;
            list.addAll(finalProofs);
          }
        }
        return list;
      }

      var rows = records();
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (f) async => pins[f.path.substring(root.path.length + 1)]!,
        startProcess: (p, args) {
          expect(args, [
            '-B',
            '${root.path}/tools/${recovery ? 'connection_recovery.py' : 'connection_bench.py'}',
          ]);
          return Process.start('/usr/bin/python3', [
            '-c',
            'import sys; sys.stdin.read(); print(sys.argv[1])',
            rows.map(jsonEncode).join('\n'),
          ]);
        },
      );
      final passed = await runner.readPairedHandshake(fixtures.actor, peers);
      expect(passed.keys, containsAll(['Link', 'Core']));
      expect(
        passed['Link']!['exchange_sha256'],
        passed['Core']!['exchange_sha256'],
      );
      for (final change in <void Function(List<Json>)>[
        (r) => r.clear(),
        (r) => r[0]['start']['carrier'] = 'other',
        (r) => r.last['attempt'] = 'other',
        if (!recovery) ...[
          (r) => r[5]['after_proof']['boot'] = '33' * 16,
          (r) => r[5]['after_proof']['challenge'] =
              r[1]['before_proof']['challenge'],
          (r) => r[3]['resources']['role'] = 'Core',
          (r) => r[2]['status']['generation'] = 2,
          (r) => r[2]['status']['state'] = 'active',
        ] else ...[
          (r) => r.firstWhere((v) => v['case'] == 'entropy')['case'] = 'other',
          (r) =>
              r.firstWhere((v) => v['case'] == 'deadline')['status']['busy'] =
                  true,
          (r) => r.firstWhere(
            (v) => v['case'] == 'continuity',
          )['status']['accepted'] = true,
          (r) => r.firstWhere((v) => v['case'] == 'stale')['status']['state'] =
              'cancelled',
          (r) => r.firstWhere(
            (v) => v.length == 2 && v.containsKey('resources'),
          )['resources']['worker_free'] = 4095,
          (r) => r.firstWhere((v) => v['trace'] != null)['trace']['bytes'] = 24,
          (r) =>
              r.firstWhere((v) => v['case'] == 'slots')['status']['fault'] = 1,
          (r) => r.firstWhere((v) => v['case'] == 'stale')['old_ticket'] = 8,
          (r) =>
              r.firstWhere((v) => v['case'] == 'signing')['status']['cleaned'] =
                  false,
          (r) => r.firstWhere(
            (v) => v['recovered_after'] == 'entropy',
          )['resources']['usb_free'] = 2047,
          (r) => r.firstWhere((v) => v['trace'] != null)['trace']['bytes'] = 1,
          (r) => r.firstWhere((v) => v['trace'] != null)['trace']['sha256'] =
              '0' * 64,
          (r) => r.firstWhere(
            (v) => v['role'] == 'Core' && v['recovered_after'] == 'Core-slots',
          )['attempt'] = 'different',
        ],
      ]) {
        rows = records();
        change(rows);
        await expectLater(
          runner.readPairedHandshake(fixtures.actor, peers),
          throwsA(anything),
        );
      }
      await expectLater(
        runner.readPairedHandshake(fixtures.actor, {'Link': peers['Link']!}),
        throwsA(anything),
      );
      await expectLater(
        runner.execute(account: fixtures.actor, command: 'connection-bench'),
        throwsA(anything),
      );
    });
  }

  test('firmware-update proof uses the pinned adapter and rejects changed bindings', () async {
    final inspection = BenchDefinition.fromSnapshot(
      await rootBundle.loadString(BenchDefinition.inspectionAsset),
    );
    final root = await Directory.systemTemp.createTemp(
      'update-proof-contract-',
    );
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...inspection.runnerFiles,
    };
    final program = await rootBundle.loadString(
      'assets/bench/claimed_update_proof.py',
    );
    final selection = <String, dynamic>{
      'role': 'Core',
      'device_id': fixtures.device,
      'serial': 'D000000000123',
      'article_id': fixtures.other,
      'article_revision_id': fixtures.revision,
      'hardware': usb.hardware,
      'source': inspection.builds.last.source,
      'public_key': '04${'11' * 64}',
    };
    final valid = <String, dynamic>{
      ...selection,
      'build': selection['source'],
      'state': 'ready',
      'busy': false,
      'failed': false,
      'boot': '22' * 16,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    var returned = valid;
    final runner = ProcessProvisioningRunner(
      root.path,
      root,
      updateProofProgram: program,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (path, args) {
        expect(args[0], '-B');
        expect(args[1], '-c');
        expect(args[2], program);
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; sys.stdin.read(); print(sys.argv[1])',
          jsonEncode({'proof': returned}),
        ]);
      },
    );
    expect(
      await runner.proveUpdateIdentity(fixtures.actor, selection, inspection),
      valid,
    );
    for (final change in [
      {'state': 'fault'},
      {'busy': true},
      {'failed': true},
      {'role': 'Link'},
      {'build': '00' * 32},
      {'hardware': '00' * 8},
      {'public_key': '04${'22' * 64}'},
      {'device_id': fixtures.other},
      {'serial': 'D000000000124'},
      {'article_id': fixtures.device},
      {'article_revision_id': fixtures.device},
      {'boot': 'bad'},
      {'challenge': 'bad'},
      {'signature': 'bad'},
    ]) {
      returned = {...valid, ...change};
      await expectLater(
        runner.proveUpdateIdentity(fixtures.actor, selection, inspection),
        throwsA(isA<ProvisioningFailure>()),
      );
    }
    final altered = ProcessProvisioningRunner(
      root.path,
      root,
      updateProofProgram: 'modified',
    );
    await expectLater(
      altered.proveUpdateIdentity(fixtures.actor, selection, inspection),
      throwsFormatException,
    );
  });

  test('inspection process is pinned and receives only the selected public binding', () async {
    final inspection = BenchDefinition.fromSnapshot(
      await rootBundle.loadString(BenchDefinition.inspectionAsset),
    );
    final root = await Directory.systemTemp.createTemp('inspection-contract-');
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...inspection.runnerFiles,
    };
    final read = admit(inspection.builds.first, guide: inspection);
    final publicKey = '04${'11' * 64}';
    final proof = <String, dynamic>{
      'state': 'ready',
      'busy': false,
      'failed': false,
      'device_id': read.device.id,
      'serial': read.device.serial,
      'article_id': read.article.articleId,
      'article_revision_id': read.article.id,
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': '22' * 16,
      'public_key': publicKey,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    final valid = <String, dynamic>{
      'v': 1,
      'id': 8,
      'ok': true,
      'type': 'credential_storage',
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'state': 'blank',
      'busy': false,
      'failed': false,
      'last_request': 7,
      'sha256': '55' * 32,
      'boot': proof['boot'],
      'identity_proof': proof,
    };
    var returned = valid;
    final runner = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (path, args) {
        expect(args, ['-B', '${root.path}/tools/credential_inspection.py']);
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; sys.stdin.read(); print(sys.argv[1])',
          jsonEncode(returned),
        ]);
      },
    );
    final response = await runner.readBenchInspection(
      fixtures.actor,
      read,
      publicKey,
    );
    expect(response, valid);
    expect(read.inspectionParameters(publicKey)['public_key'], publicKey);
    for (final change in [
      {'identity_proof': null},
      {'v': 2},
      {'ok': false},
      {'id': 0},
      {'role': 'Core'},
      {'build': '00' * 32},
      {'hardware': '00' * 8},
      {'state': 'unavailable'},
      {'busy': true},
      {'failed': true},
      {'last_request': 0},
      {'sha256': 'bad'},
      {'boot': '00' * 16},
      {
        'identity_proof': {...proof, 'public_key': '04${'22' * 64}'},
      },
      {
        'identity_proof': {...proof, 'challenge': 'bad'},
      },
      {
        'identity_proof': {...proof, 'signature': 'bad'},
      },
      {
        'identity_proof': {...proof, 'challenge': '0' * 64},
      },
      {
        'boot': '0' * 32,
        'identity_proof': {...proof, 'boot': '0' * 32},
      },
    ]) {
      returned = {...valid, ...change};
      await expectLater(
        runner.readBenchInspection(fixtures.actor, read, publicKey),
        throwsA(isA<ProvisioningFailure>()),
      );
    }
    await expectLater(
      runner.readBenchInspection(fixtures.actor, read, 'a' * 9000),
      throwsFormatException,
    );
    final failure = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (_, _) => Process.start('/usr/bin/false', []),
    );
    await expectLater(
      failure.readBenchInspection(fixtures.actor, read, publicKey),
      throwsA(isA<ProvisioningFailure>()),
    );
  });

  test('delivery runner retains only bound public proof evidence', () async {
    final guide = BenchDefinition.fromSnapshot(
      await rootBundle.loadString(BenchDefinition.readinessAsset),
    );
    final root = await Directory.systemTemp.createTemp('delivery-contract-');
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...guide.runnerFiles,
    };
    final read = admit(guide.builds.first, guide: guide),
        key = '04${'11' * 64}';
    final credential = PublicFactoryCredential.fromJson(
      {
        'v': 1,
        'device_id': read.device.id,
        'role': read.build.role,
        'credential': '010203',
        'credential_sha256':
            '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
      },
      deviceId: read.device.id,
      role: read.build.role,
      expectedDigest:
          '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
    );
    final identity = <String, dynamic>{
      'v': 1,
      'ok': true,
      'type': 'identity',
      'algorithm': 'P256-SHA256',
      'state': 'ready',
      'busy': false,
      'failed': false,
      'device_id': read.device.id,
      'serial': read.device.serial,
      'article_id': read.article.articleId,
      'article_revision_id': read.article.id,
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': '22' * 16,
      'public_key': key,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    final proof = <String, dynamic>{
      'v': 1,
      'id': 9,
      'ok': true,
      'type': 'credential_delivery',
      'role': read.build.role,
      'build': read.build.source,
      'boot': identity['boot'],
      'hardware': read.device.hardwareUid,
      'device_id': read.device.id,
      'serial': read.device.serial,
      'article_id': read.article.articleId,
      'article_revision_id': read.article.id,
      'transfer_id': 1,
      'challenge': '55' * 32,
      'credential_revision': 1,
      'content_id': '66' * 32,
      'envelope_sha256': credential.digest,
      'signature': '77' * 64,
    };
    Json returned = {'identity_proof': identity, 'delivery_proof': proof};
    final runner = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (_, args) {
        expect(args, ['-B', '${root.path}/tools/credential_delivery.py']);
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; sys.stdin.read(); print(sys.argv[1])',
          jsonEncode(returned),
        ]);
      },
    );
    expect(
      await runner.readBenchDelivery(fixtures.actor, read, key, credential),
      returned,
    );
    for (final change in <Json>[
      {'boot': 'ff' * 16},
      {'device_id': fixtures.other},
      {'role': 'Core'},
      {'envelope_sha256': 'ff' * 32},
      {'challenge': identity['challenge']},
      {'content_id': '0' * 64},
      {'signature': '0' * 128},
      {'extra': 'private'},
    ]) {
      returned = {
        'identity_proof': identity,
        'delivery_proof': {...proof, ...change},
      };
      await expectLater(
        runner.readBenchDelivery(fixtures.actor, read, key, credential),
        throwsA(isA<ProvisioningFailure>()),
      );
    }
  });

  test('readiness runner verifies inspection, proof, boot and state', () async {
    final guide = BenchDefinition.fromSnapshot(
      await rootBundle.loadString(BenchDefinition.readinessAsset),
    );
    final root = await Directory.systemTemp.createTemp('readiness-contract-');
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...guide.runnerFiles,
    };
    final read = admit(guide.builds.first, guide: guide);
    final key = '04${'11' * 64}';
    final proof = <String, dynamic>{
      'state': 'ready',
      'busy': false,
      'failed': false,
      'device_id': read.device.id,
      'serial': read.device.serial,
      'article_id': read.article.articleId,
      'article_revision_id': read.article.id,
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': '22' * 16,
      'public_key': key,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    final inspection = <String, dynamic>{
      'v': 1,
      'id': 8,
      'ok': true,
      'type': 'credential_storage',
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'state': 'blank',
      'busy': false,
      'failed': false,
      'last_request': 7,
      'sha256': '55' * 32,
      'boot': proof['boot'],
      'identity_proof': proof,
    };
    final valid = <String, dynamic>{
      'v': 1,
      'id': 9,
      'ok': true,
      'type': 'credential_readiness',
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': proof['boot'],
      'state': 'empty',
      'revision': 0,
      'content_id': '',
      'inspection': inspection,
      'identity_proof': proof,
    };
    var returned = valid;
    final runner = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (path, args) {
        expect(args, ['-B', '${root.path}/tools/credential_readiness.py']);
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; sys.stdin.read(); print(sys.argv[1])',
          jsonEncode(returned),
        ]);
      },
    );
    expect(await runner.readBenchReadiness(fixtures.actor, read, key), valid);
    for (final change in [
      {
        'state': 'ready',
        'revision': 1,
        'content_id': 'aa' * 32,
        'inspection': {...inspection, 'state': 'recognizable'},
      },
      {
        'state': 'pending',
        'inspection': {...inspection, 'state': 'interrupted'},
      },
    ]) {
      returned = {...valid, ...change};
      expect(
        await runner.readBenchReadiness(fixtures.actor, read, key),
        returned,
      );
    }
    for (final change in [
      {'inspection': null},
      {'identity_proof': null},
      {'boot': 'ff' * 16},
      {'state': 'unavailable'},
      {'state': 'ready', 'revision': 1, 'content_id': 'aa' * 32},
      {'revision': 1},
      {'content_id': 'aa' * 32},
      {'hardware': 'ff' * 8},
      {'build': 'ff' * 32},
      {'id': 0},
      {
        'inspection': {
          ...inspection,
          'identity_proof': {...proof, 'public_key': '04${'22' * 64}'},
        },
      },
      {
        'inspection': {...inspection, 'sha256': 'bad'},
      },
    ]) {
      returned = {...valid, ...change};
      await expectLater(
        runner.readBenchReadiness(fixtures.actor, read, key),
        throwsA(isA<ProvisioningFailure>()),
      );
    }
  });

  test(
    'only the reviewed guide binds the read, even after a caller edits a view',
    () {
      expect(definition.guide['key'], 'provisioned-identity');
      expect(definition.guide['revision'], 2);
      expect(definition.guide['steps'], hasLength(7));
      definition.guide['runner']['id'] = 'install';
      expect(definition.guide['runner']['id'], 'p1.identity');
      for (final changed in [
        snapshot.replaceFirst('"revision": 2', '"revision": 3'),
        snapshot.replaceFirst('p1.identity', 'install'),
        snapshot.replaceFirst('"number": 2', '"number": 8'),
        snapshot.replaceFirst('Read the serial', 'Guess the serial'),
        '{}',
      ]) {
        expect(
          () => BenchDefinition.fromSnapshot(changed),
          throwsFormatException,
        );
      }
    },
  );

  test(
    'retains the exact legacy definition and its original runner pins',
    () async {
      final legacy = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(BenchDefinition.legacyAsset),
      );
      expect(legacy.snapshotDigest, BenchDefinition.legacyDigest);
      expect(legacy.guide['revision'], 1);
      expect(legacy.runnerFiles, hasLength(5));
      expect(definition.runnerFiles.length, greaterThan(5));
    },
  );

  test('requires the registered revision, application target and exact role image tuple', () {
    final link = definition.builds.first;
    final core = definition.builds.last;
    final blocked = throwsA(isA<ProvisioningFailure>());
    expect(
      () => admit(link, device: {'provisioning_state': 'reserved'}),
      blocked,
    );
    expect(
      () => admit(link, device: {'article_revision_id': fixtures.other}),
      blocked,
    );
    expect(() => admit(link, device: {'hardware_uid': null}), blocked);
    expect(() => admit(link, target: {'hardware': '1' * 16}), blocked);
    expect(() => admit(link, target: usb.targetJson('bootloader')), blocked);
    expect(() => admit(link, article: {'role': 'Core'}), blocked);
    for (final bad in [
      (
        role: 'Phone',
        version: link.version,
        source: link.source,
        artifact: link.artifact,
      ),
      (
        role: link.role,
        version: '0.4.1',
        source: link.source,
        artifact: link.artifact,
      ),
      (
        role: link.role,
        version: link.version,
        source: link.source.substring(0, 8),
        artifact: link.artifact,
      ),
      (
        role: link.role,
        version: link.version,
        source: link.source,
        artifact: core.artifact,
      ),
    ]) {
      expect(() => admit(bad), blocked);
    }
  });

  test('shared process action with explicit role for claimed CORE and unclaimed LINK', () async {
    final root = await Directory.systemTemp.createTemp('identity-contract-');
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...definition.runnerFiles,
    };
    final checked = <String>{};
    var launches = 0;
    for (final build in definition.builds) {
      final read = admit(build);
      final frame = {
        'state': 'ready',
        'busy': false,
        'failed': false,
        'device_id': fixtures.device,
        'serial': read.device.serial,
        'article_id': fixtures.other,
        'article_revision_id': fixtures.revision,
      };
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async {
          final name = file.path.substring(root.path.length + 1);
          checked.add(name);
          return pins[name]!;
        },
        startProcess: (path, args) {
          launches++;
          expect(args, [
            '-B',
            '${root.path}/tools/provision.py',
            'identity',
            '--hardware',
            usb.hardware,
            '--source',
            build.source,
            '--role',
            build.role,
          ]);
          return Process.start('/bin/echo', [jsonEncode(frame)]);
        },
      );
      expect(await runner.readBenchIdentity(fixtures.actor, read), frame);
      expect(checked, pins.keys.toSet());
      for (final change in [
        {'state': 'empty'},
        {'state': 'pending'},
        {'state': 'fault'},
        {'busy': true},
        {'failed': true},
        {'device_id': fixtures.other},
        {'serial': 'D000000000124'},
        {'article_id': fixtures.device},
        {'article_revision_id': fixtures.device},
      ]) {
        expect(
          () => read.checkRegistryIdentity({...frame, ...change}),
          throwsA(isA<ProvisioningFailure>()),
        );
      }
    }
    for (final name in definition.runnerFiles.keys) {
      final original = pins[name]!;
      pins[name] = '0' * 64;
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async =>
            pins[file.path.substring(root.path.length + 1)]!,
        startProcess: (_, _) =>
            throw StateError('Must stop before process start'),
      );
      await expectLater(
        runner.readBenchIdentity(
          fixtures.actor,
          admit(definition.builds.first),
        ),
        throwsFormatException,
      );
      pins[name] = original;
    }
    final unavailable = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (_, _) => Process.start('/usr/bin/false', []),
    );
    await expectLater(
      unavailable.readBenchIdentity(
        fixtures.actor,
        admit(definition.builds.first),
      ),
      throwsA(
        isA<ProvisioningFailure>().having(
          (e) => e.message,
          'diagnostic',
          contains('identity read failed'),
        ),
      ),
    );
    final commands = <String>[];
    final wrongTarget = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (path, args) {
        commands.add(args[2]);
        if (args[2] == 'inventory') {
          return Process.start('/bin/echo', ['{"targets":[],"builds":[]}']);
        }
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; print("Connected device or firmware does not match selection", file=sys.stderr); sys.exit(1)',
        ]);
      },
    );
    expect(await wrongTarget.discoverBench(fixtures.actor, definition), {
      'targets': [],
      'builds': [],
    });
    Json? diagnostic;
    await expectLater(
      wrongTarget.readBenchIdentity(
        fixtures.actor,
        admit(definition.builds.first),
        onDiagnostic: (d) => diagnostic = d,
      ),
      throwsA(isA<BenchBlocked>()),
    );
    expect(diagnostic!['exit_code'], 1);
    expect(commands, ['inventory', 'identity']);
    expect(launches, definition.builds.length);
  });
  test(
    'crypto probe runner binds identity, boot, build and successful checks',
    () async {
      final guide = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(BenchDefinition.cryptoProbeAsset),
      );
      final root = await Directory.systemTemp.createTemp('crypto-contract-');
      addTearDown(() => root.delete(recursive: true));
      for (final lock in [
        'usb-provisioning.lock.json',
        'control-storage.lock.json',
      ]) {
        await File('vendor/$lock').copy('${root.path}/$lock');
      }
      final pins = {
        ...ProcessProvisioningRunner.pins,
        ...ProcessProvisioningRunner.controlPins,
        ...guide.runnerFiles,
      };
      final read = admit(guide.builds.first, guide: guide);
      final key = '04${'11' * 64}';
      final proof = <String, dynamic>{
        'state': 'ready',
        'busy': false,
        'failed': false,
        'device_id': read.device.id,
        'serial': read.device.serial,
        'article_id': read.article.articleId,
        'article_revision_id': read.article.id,
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': '22' * 16,
        'public_key': key,
        'challenge': '33' * 32,
        'signature': '44' * 64,
      };
      final after = {...proof, 'challenge': '55' * 32};
      final frame = <String, dynamic>{
        'v': 1,
        'id': 8,
        'ok': true,
        'type': 'crypto_probe',
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': proof['boot'],
        'run_id': 1,
        'state': 'passed',
        'cancel_requested': false,
        'hash': true,
        'signature': true,
        'agreement': true,
        'random': true,
        'stack_free_words': 777,
        'elapsed_ms': null,
      };
      final valid = <String, dynamic>{
        'outcome': 'passed',
        'before_proof': proof,
        'after_proof': after,
        'frame': frame,
        'host_elapsed_ms': 42,
      };
      var returned = valid;
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async =>
            pins[file.path.substring(root.path.length + 1)]!,
        startProcess: (path, args) {
          expect(args, ['-B', '${root.path}/tools/crypto_probe.py']);
          return Process.start('/usr/bin/python3', [
            '-c',
            'import sys; sys.stdin.read(); print(sys.argv[1])',
            jsonEncode(returned),
          ]);
        },
      );
      expect(await runner.readCryptoProbe(fixtures.actor, read, key), valid);
      returned = {
        ...valid,
        'frame': {...frame, 'elapsed_ms': 5},
      };
      expect(
        (await runner.readCryptoProbe(fixtures.actor, read, key))['outcome'],
        'passed',
      );
      for (final change in [
        {'before_proof': null},
        {
          'after_proof': {...after, 'boot': '66' * 16},
        },
        {
          'after_proof': {...after, 'challenge': proof['challenge']},
        },
        {
          'frame': {...frame, 'run_id': 0},
        },
        {
          'frame': {...frame, 'boot': '66' * 16},
        },
        {
          'frame': {...frame, 'hash': false},
        },
        {
          'frame': {...frame, 'stack_free_words': null},
        },
        {
          'frame': {...frame, 'cancel_requested': true},
        },
        {
          'frame': {...frame, 'elapsed_ms': -1},
        },
        {
          'frame': {...frame, 'elapsed_ms': 0x100000000},
        },
        {'host_elapsed_ms': null},
      ]) {
        returned = {...valid, ...change};
        await expectLater(
          runner.readCryptoProbe(fixtures.actor, read, key),
          throwsA(isA<ProvisioningFailure>()),
        );
      }
      returned = {
        'outcome': 'interrupted',
        'frame': frame,
        'error': 'lost response',
      };
      expect(
        (await runner.readCryptoProbe(fixtures.actor, read, key))['outcome'],
        'interrupted',
      );
    },
  );
  test('reentry runner requires every independent safety result', () async {
    final guide = BenchDefinition.fromSnapshot(
      await rootBundle.loadString(BenchDefinition.cryptoReentryAsset),
    );
    final root = await Directory.systemTemp.createTemp('reentry-contract-');
    addTearDown(() => root.delete(recursive: true));
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...guide.runnerFiles,
    };
    final read = admit(guide.builds.first, guide: guide);
    final key = '04${'11' * 64}';
    final proof = <String, dynamic>{
      'state': 'ready',
      'busy': false,
      'failed': false,
      'device_id': read.device.id,
      'serial': read.device.serial,
      'article_id': read.article.articleId,
      'article_revision_id': read.article.id,
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': '22' * 16,
      'public_key': key,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    final frame = <String, dynamic>{
      'v': 1,
      'id': 8,
      'ok': true,
      'type': 'crypto_reentry',
      'role': read.build.role,
      'build': read.build.source,
      'hardware': read.device.hardwareUid,
      'boot': proof['boot'],
      'run_id': 1,
      'state': 'passed',
      'cancel_requested': false,
      'nested_refused': true,
      'outer_failed': true,
      'output_cleared': true,
      'input_intact': true,
      'later_hash': true,
      'stack_free_words': 777,
    };
    final valid = <String, dynamic>{
      'outcome': 'passed',
      'before_proof': proof,
      'after_proof': {...proof, 'challenge': '55' * 32},
      'frame': frame,
      'host_elapsed_ms': 42,
    };
    var returned = valid;
    final runner = ProcessProvisioningRunner(
      root.path,
      root,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (path, args) {
        expect(args, ['-B', '${root.path}/tools/crypto_probe.py', '--reentry']);
        return Process.start('/usr/bin/python3', [
          '-c',
          'import sys; sys.stdin.read(); print(sys.argv[1])',
          jsonEncode(returned),
        ]);
      },
    );
    expect(await runner.readCryptoProbe(fixtures.actor, read, key), valid);
    for (final name in [
      'nested_refused',
      'outer_failed',
      'output_cleared',
      'input_intact',
      'later_hash',
    ]) {
      returned = {
        ...valid,
        'frame': {...frame, name: false},
      };
      await expectLater(
        runner.readCryptoProbe(fixtures.actor, read, key),
        throwsA(isA<ProvisioningFailure>()),
      );
    }
    returned = {
      ...valid,
      'frame': {...frame, 'type': 'crypto_probe'},
    };
    await expectLater(
      runner.readCryptoProbe(fixtures.actor, read, key),
      throwsA(isA<ProvisioningFailure>()),
    );
  });
  test(
    'RTC2 runner validates boot, build, signed identity and timed waits',
    () async {
      final guide = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(BenchDefinition.rtc2Asset),
      );
      final root = await Directory.systemTemp.createTemp('rtc2-contract-');
      addTearDown(() => root.delete(recursive: true));
      for (final lock in [
        'usb-provisioning.lock.json',
        'control-storage.lock.json',
      ]) {
        await File('vendor/$lock').copy('${root.path}/$lock');
      }
      final pins = {
        ...ProcessProvisioningRunner.pins,
        ...ProcessProvisioningRunner.controlPins,
        ...guide.runnerFiles,
      };
      final read = admit(guide.builds.first, guide: guide);
      final key = '04${'11' * 64}';
      final proof = <String, dynamic>{
        'state': 'ready',
        'busy': false,
        'failed': false,
        'device_id': read.device.id,
        'serial': read.device.serial,
        'article_id': read.article.articleId,
        'article_revision_id': read.article.id,
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': '22' * 16,
        'public_key': key,
        'challenge': '33' * 32,
        'signature': '44' * 64,
      };
      final frame = <String, dynamic>{
        'type': 'rtc2_observation',
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': proof['boot'],
        'state': 2,
        'waits': 1,
        'longest_wait_ticks': 3,
      };
      final summary = <String, dynamic>{
        'definition': 'c83-rtc2-observation.v2',
        'mode': 'quick',
        'outcome': 'observed',
        'role': read.build.role,
        'source': read.build.source,
        'artifact': read.build.artifact,
        'wait_path_observed': true,
        'host_relative_rate_error_ppb': [-100, 200],
        'full_temperature_rate_bound': 'unqualified',
      };
      final endProof = {...proof, 'challenge': '55' * 32};
      final start = {
        'command': 'rtc2-sample',
        'frame': frame,
        'before_ns': 20,
        'ticks': 10,
      };
      final end = {
        'command': 'rtc2-idle',
        'frame': {...frame, 'waits': 6},
        'after_ns': 6000000020,
        'ticks': 6154,
      };
      final valid = <Json>[
        {'start': {}},
        {'before_proof': proof},
        {
          'command': 'rtc2-sample',
          'frame': {...frame, 'state': 1},
        },
        start,
        end,
        {'after_proof': endProof},
        {'result': summary},
      ];
      List<dynamic> rows = valid;
      int exitCode = 0;
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async =>
            pins[file.path.substring(root.path.length + 1)]!,
        startProcess: (path, args) {
          expect(args, ['-B', '${root.path}/tools/rtc2_observe.py', 'quick']);
          return Process.start('/usr/bin/python3', [
            '-c',
            'import sys; sys.stdin.read(); print(sys.argv[1]); sys.exit(int(sys.argv[2]))',
            rows.map(jsonEncode).join('\n'),
            exitCode.toString(),
          ]);
        },
      );
      expect(
        (await runner.readRtc2(fixtures.actor, read, key))['outcome'],
        'passed',
      );
      for (final bad in <List<dynamic>>[
        [
          {'start': {}},
        ],
        [...valid.take(4), 1, ...valid.skip(5)],
        [
          ...valid.take(6),
          {
            'result': {...summary, 'source': '0' * 64},
          },
        ],
        [
          ...valid.take(5),
          {
            'after_proof': {...endProof, 'hardware': 'ff' * 8},
          },
          valid.last,
        ],
        [
          ...valid.take(5),
          {'after_proof': proof},
          valid.last,
        ],
        [
          ...valid.take(4),
          {
            'frame': {...frame, 'state': 4},
          },
          ...valid.skip(5),
        ],
        [
          ...valid.take(4),
          {...end, 'frame': frame},
          ...valid.skip(5),
        ],
        [
          ...valid.take(6),
          {
            'result': {
              ...summary,
              'host_relative_rate_error_ppb': [10, 1],
            },
          },
        ],
      ]) {
        rows = bad;
        await expectLater(
          runner.readRtc2(fixtures.actor, read, key),
          throwsA(isA<ProvisioningFailure>()),
        );
      }
      exitCode = 1;
      const reason = 'No positive System ON idle wait was observed';
      rows = [
        {
          'result': {'outcome': 'interrupted', 'error': reason},
        },
      ];
      final interrupted = await runner.readRtc2(fixtures.actor, read, key);
      expect(interrupted['outcome'], 'interrupted');
      expect(interrupted['error'], reason);
      rows = [
        {'start': {}},
      ];
      await expectLater(
        runner.readRtc2(fixtures.actor, read, key),
        throwsA(isA<ProvisioningFailure>()),
      );
    },
  );
  test(
    'key runner requires every lifecycle result and rejects signature data',
    () async {
      final guide = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(BenchDefinition.cryptoKeysAsset),
      );
      final root = await Directory.systemTemp.createTemp('keys-contract-');
      addTearDown(() => root.delete(recursive: true));
      for (final lock in [
        'usb-provisioning.lock.json',
        'control-storage.lock.json',
      ]) {
        await File('vendor/$lock').copy('${root.path}/$lock');
      }
      final pins = {
        ...ProcessProvisioningRunner.pins,
        ...ProcessProvisioningRunner.controlPins,
        ...guide.runnerFiles,
      };
      final read = admit(guide.builds.first, guide: guide);
      final key = '04${'11' * 64}';
      final proof = <String, dynamic>{
        'state': 'ready',
        'busy': false,
        'failed': false,
        'device_id': read.device.id,
        'serial': read.device.serial,
        'article_id': read.article.articleId,
        'article_revision_id': read.article.id,
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': '22' * 16,
        'public_key': key,
        'challenge': '33' * 32,
        'signature': '44' * 64,
      };
      final frame = <String, dynamic>{
        'v': 1,
        'id': 8,
        'ok': true,
        'type': 'crypto_keys',
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': proof['boot'],
        'run_id': 1,
        'state': 'passed',
        'cancel_requested': false,
        'identity_signature': true,
        'agreement': true,
        'exhaustion': true,
        'stale_rejected': true,
        'cleaned': true,
        'stack_free_words': 777,
      };
      final valid = <String, dynamic>{
        'outcome': 'passed',
        'before_proof': proof,
        'after_proof': {...proof, 'challenge': '55' * 32},
        'frame': frame,
        'host_elapsed_ms': 42,
      };
      var returned = valid;
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async =>
            pins[file.path.substring(root.path.length + 1)]!,
        startProcess: (path, args) {
          expect(args, ['-B', '${root.path}/tools/crypto_probe.py', '--keys']);
          return Process.start('/usr/bin/python3', [
            '-c',
            'import sys; sys.stdin.read(); print(sys.argv[1])',
            jsonEncode(returned),
          ]);
        },
      );
      expect(await runner.readCryptoProbe(fixtures.actor, read, key), valid);
      for (final name in [
        'identity_signature',
        'agreement',
        'exhaustion',
        'stale_rejected',
        'cleaned',
      ]) {
        returned = {
          ...valid,
          'frame': {...frame, name: false},
        };
        await expectLater(
          runner.readCryptoProbe(fixtures.actor, read, key),
          throwsA(isA<ProvisioningFailure>()),
        );
      }
      returned = {
        ...valid,
        'frame': {...frame, 'signature': 'must not escape'},
      };
      await expectLater(
        runner.readCryptoProbe(fixtures.actor, read, key),
        throwsA(isA<ProvisioningFailure>()),
      );
      returned = {
        ...valid,
        'frame': {...frame, 'type': 'crypto_probe'},
      };
      await expectLater(
        runner.readCryptoProbe(fixtures.actor, read, key),
        throwsA(isA<ProvisioningFailure>()),
      );
    },
  );
  test(
    'startup runner binds result to exact selection and signed proofs',
    () async {
      final guide = BenchDefinition.fromSnapshot(
        await rootBundle.loadString(BenchDefinition.startupDiagnosticsAsset),
      );
      final root = await Directory.systemTemp.createTemp('startup-contract-');
      addTearDown(() => root.delete(recursive: true));
      for (final lock in [
        'usb-provisioning.lock.json',
        'control-storage.lock.json',
      ]) {
        await File('vendor/$lock').copy('${root.path}/$lock');
      }
      final pins = {
        ...ProcessProvisioningRunner.pins,
        ...ProcessProvisioningRunner.controlPins,
        ...guide.runnerFiles,
      };
      final read = admit(guide.builds.first, guide: guide);
      final key = '04${'11' * 64}';
      final proof = <String, dynamic>{
        'state': 'ready',
        'busy': false,
        'failed': false,
        'device_id': read.device.id,
        'serial': read.device.serial,
        'article_id': read.article.articleId,
        'article_revision_id': read.article.id,
        'role': read.build.role,
        'build': read.build.source,
        'hardware': read.device.hardwareUid,
        'boot': '22' * 16,
        'public_key': key,
        'challenge': '33' * 32,
        'signature': '44' * 64,
      };
      final after = {...proof, 'challenge': '55' * 32};
      final frame = <String, dynamic>{
        'v': 1,
        'ok': true,
        'type': 'tests',
        'role': read.build.role,
        'build': read.build.source,
        'run_id': 1,
        'running': false,
        'results': [
          for (final id in BenchSession.startupChecks.skip(1))
            {'id': id, 'result': 'passed'},
        ],
      };
      final valid = <String, dynamic>{
        'selection': 'all',
        'outcome': 'passed',
        'before_proof': proof,
        'after_proof': after,
        'frame': frame,
        'error': null,
      };
      var returned = valid;
      final runner = ProcessProvisioningRunner(
        root.path,
        root,
        fileDigest: (file) async =>
            pins[file.path.substring(root.path.length + 1)]!,
        startProcess: (path, args) {
          expect(args, ['-B', '${root.path}/tools/startup_diagnostics.py']);
          return Process.start('/usr/bin/python3', [
            '-c',
            'import sys; sys.stdin.read(); print(sys.argv[1])',
            jsonEncode(returned),
          ]);
        },
      );
      expect(
        await runner.readStartupDiagnostics(fixtures.actor, read, key, 'all'),
        valid,
      );
      for (final change in [
        {'before_proof': null},
        {'after_proof': null},
        {'frame': null},
        {
          'before_proof': {...proof, 'public_key': 'bad'},
        },
        {
          'after_proof': {...after, 'boot': '66' * 16},
        },
        {
          'after_proof': {...after, 'challenge': proof['challenge']},
        },
        {
          'frame': {...frame, 'running': true},
        },
        {
          'frame': {...frame, 'run_id': 0},
        },
        {
          'frame': {...frame, 'role': 'Core'},
        },
        {
          'frame': {...frame, 'results': []},
        },
        {
          'frame': {
            ...frame,
            'results': [
              for (final id in BenchSession.startupChecks.skip(1))
                {'id': id, 'result': 'not_run'},
            ],
          },
        },
      ]) {
        returned = {...valid, ...change};
        await expectLater(
          runner.readStartupDiagnostics(fixtures.actor, read, key, 'all'),
          throwsA(isA<ProvisioningFailure>()),
        );
      }
      returned = {
        'selection': 'all',
        'outcome': 'failed',
        'frame': frame,
        'error': 'device failed',
      };
      expect(
        (await runner.readStartupDiagnostics(
          fixtures.actor,
          read,
          key,
          'all',
        ))['outcome'],
        'failed',
      );
      returned = {...valid, 'selection': 'clock'};
      await expectLater(
        runner.readStartupDiagnostics(fixtures.actor, read, key, 'all'),
        throwsA(isA<ProvisioningFailure>()),
      );
      await expectLater(
        runner.readStartupDiagnostics(fixtures.actor, read, key, 'bad'),
        throwsFormatException,
      );
    },
  );
}
