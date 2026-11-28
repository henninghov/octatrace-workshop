import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/claimed_update.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

const account = '11111111-1111-4111-8111-111111111111';
const otherAccount = '22222222-2222-4222-8222-222222222222';
const deviceId = '33333333-3333-4333-8333-333333333333';
const articleId = '44444444-4444-4444-8444-444444444444';
const revisionId = '55555555-5555-4555-8555-555555555555';
const hardware = '1111111111111111';
final key = '04${'22' * 64}';
const oldSource =
    '0732191cbe923516aa34a5dd0c43359cdfc4b2fcadf4ba8738ae16966afc331e';
const newSource =
    '93dd066c1d5a872a4335d11f7cf50d08b87cd3192898856ab4c924583c94f36e';
const artifact =
    'a862a12f4f4f361d2d0c9084fed52c5c99c47457076778fa9e35fef63bc0a397';

Json deviceJson({String? owner = account}) => {
  'id': deviceId,
  'serial': 'D123456789012',
  'article_revision_id': revisionId,
  'provisioning_state': 'provisioned',
  'owner_user_id': owner,
  'hardware_uid': hardware,
};
final device = DeviceRecord.fromJson(deviceJson());
final article = ArticleRevision.fromJson({
  'id': revisionId,
  'article_id': articleId,
  'code': 'SYNTHETIC',
  'name': 'Synthetic CORE',
  'role': 'Core',
  'revision': 1,
  'case_version': '1',
  'parts': <Object>[],
});
Json event() {
  Json frame(String boot) => {
    'state': 'ready',
    'device_id': device.id,
    'serial': device.serial,
    'article_id': article.articleId,
    'article_revision_id': article.id,
    'hardware': hardware,
    'role': 'Core',
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
      'verification': {'before': frame('a' * 32), 'after': frame('b' * 32)},
    },
  };
}

class Gateway implements WorkshopGateway {
  String? currentAccount = account;
  Json selected = deviceJson();
  bool denied = false, missingKey = false;
  int authorizations = 0;
  @override
  String? get accountId => currentAccount;
  @override
  Future<void> authorizeOperator() async {
    authorizations++;
    if (denied) throw OperatorDenied();
  }

  @override
  Future<Registry> load() async => Registry.fromJson({
    'devices': [selected],
    'articles': [
      {
        'id': revisionId,
        'article_id': articleId,
        'code': 'SYNTHETIC',
        'name': 'Synthetic CORE',
        'role': 'Core',
        'revision': 1,
        'case_version': '1',
        'parts': <Object>[],
      },
    ],
    'runs': missingKey ? <Object>[] : [event()],
  });
  @override
  dynamic noSuchMethod(Invocation i) => super.noSuchMethod(i);
}

class Runner implements ProvisioningRunner {
  String mode = 'app';
  String buildSource = newSource, buildArtifact = artifact;
  bool noTarget = false, noBuild = false, badInstall = false;
  Object? installFailure;
  final commands = <String>[];
  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    commands.add(command);
    if (command == 'inventory') {
      return {
        'targets': noTarget
            ? <Object>[]
            : [
                {
                  'hardware': hardware,
                  'mode': mode,
                  'label': 'synthetic',
                  if (mode == 'bootloader') 'volume': '/Volumes/SYNTHETIC',
                },
              ],
        'builds': noBuild
            ? <Object>[]
            : [
                {
                  'role': 'Core',
                  'source': buildSource,
                  'artifact': buildArtifact,
                  'version': '0.4.0',
                  'manifest': '/synthetic/manifest.json',
                  'label': 'CORE',
                },
              ],
      };
    }
    if (installFailure != null) throw installFailure!;
    return {
      'installed': true,
      'hardware': hardware,
      'source': buildSource,
      'artifact': badInstall ? '0' * 64 : buildArtifact,
    };
  }

  @override
  Future<void> cancel() async {}
}

void main() {
  late Directory temp;
  late EvidenceJournal store;
  late Gateway gateway;
  late Runner runner;
  late String guide;
  late BenchDefinition definition;
  var serial = 0;
  var current = true;
  var sameBoot = false;
  var bootBeforeSource = oldSource;
  var proofFails = false;
  var postProofFails = false;
  final calls = <String>[];
  Future<Json> proof(String account, Json selection, BenchDefinition _) async {
    calls.add(selection['source']);
    if (proofFails || (postProofFails && selection['source'] == newSource)) {
      throw const FormatException('proof failed');
    }
    return {
      ...selection,
      'build': selection['source'],
      'state': 'ready',
      'busy': false,
      'failed': false,
      'public_key': key,
      'challenge': 'c' * 64,
      'signature': 'd' * 128,
      'boot': selection['source'] == bootBeforeSource || sameBoot
          ? 'a' * 32
          : 'b' * 32,
    };
  }

  ClaimedUpdateSession session({String? snapshot}) => ClaimedUpdateSession(
    account: account,
    device: device,
    article: article,
    gateway: gateway,
    runner: runner,
    prove: proof,
    store: store,
    definition: definition,
    guideSnapshot: snapshot ?? guide,
    now: () => DateTime.utc(2026, 11, 22),
    workshopFingerprint: () async => 'f' * 64,
    newId: () =>
        'aaaaaaaa-aaaa-4aaa-8aaa-${(++serial).toString().padLeft(12, '0')}',
    current: () => current,
  );
  setUp(() async {
    temp = await Directory.systemTemp.createTemp('claimed-update-test-');
    store = EvidenceJournal(temp);
    gateway = Gateway();
    runner = Runner();
    guide = File('assets/bench/claimed-firmware-update.v1.json')
        .readAsStringSync();
    definition = BenchDefinition.fromSnapshot(
      File(BenchDefinition.inspectionAsset).readAsStringSync(),
    );
    current = true;
    sameBoot = false;
    bootBeforeSource = oldSource;
    proofFails = false;
    postProofFails = false;
    calls.clear();
  });
  tearDown(() async => temp.delete(recursive: true));

  test('readiness CORE update uses a separate immutable guide', () {
    final snapshot = File('assets/bench/claimed-firmware-update.v2.json')
        .readAsStringSync();
    final update = session(snapshot: snapshot);
    final readiness = BenchDefinition.fromSnapshot(
      File(BenchDefinition.legacyReadinessAsset).readAsStringSync(),
    );
    final core = readiness.builds.singleWhere((b) => b.role == 'Core');
    expect(update.guide['revision'], 2);
    expect(update.guide['before_source'], newSource);
    expect(update.guide['after_source'], core.source);
    expect(update.guide['after_artifact'], core.artifact);
    expect(
      () => session(snapshot: snapshot.replaceFirst(core.source, '0' * 64)),
      throwsFormatException,
    );
  });

  test('delivery CORE update is bound to the prior and new exact builds', () {
    final snapshot = File('assets/bench/claimed-firmware-update.v3.json')
        .readAsStringSync();
    final update = session(snapshot: snapshot);
    final previous = BenchDefinition.fromSnapshot(
      File(BenchDefinition.legacyReadinessAsset).readAsStringSync(),
    );
    final next = BenchDefinition.fromSnapshot(
      File(BenchDefinition.deliveryAsset).readAsStringSync(),
    );
    final core = next.builds.singleWhere((b) => b.role == 'Core');
    expect(update.guide['revision'], 3);
    expect(
      update.guide['before_source'],
      previous.builds.singleWhere((b) => b.role == 'Core').source,
    );
    expect(update.guide['after_source'], core.source);
    expect(update.guide['after_artifact'], core.artifact);
    expect(
      () => session(snapshot: snapshot.replaceFirst(core.source, '0' * 64)),
      throwsFormatException,
    );
  });
  test('installation CORE update binds the current delivery image to the installation build', () {
    final update = session(
      snapshot: File('assets/bench/claimed-firmware-update.v4.json')
          .readAsStringSync(),
    );
    final old = BenchDefinition.fromSnapshot(
      File(BenchDefinition.deliveryAsset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    final next = BenchDefinition.fromSnapshot(
      File(BenchDefinition.installationAsset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    expect(update.guide['revision'], 4);
    expect(update.guide['before_source'], old.source);
    expect(update.guide['after_source'], next.source);
    expect(update.guide['after_artifact'], next.artifact);
  });

  test(
    'inspection update binds the prior CORE and the new qualified artifact',
    () {
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.recoveryAsset).readAsStringSync(),
      );
      definition = BenchDefinition.fromSnapshot(
        File(BenchDefinition.authorityAsset).readAsStringSync(),
      );
      final selected = definition.builds.singleWhere(
        (build) => build.role == 'Core',
      );
      final update = session(
        snapshot: File('assets/bench/claimed-firmware-update.v12.json')
            .readAsStringSync(),
      );
      expect(
        update.guide['before_source'],
        previous.builds.singleWhere((build) => build.role == 'Core').source,
      );
      expect(update.guide['after_source'], selected.source);
      expect(update.guide['after_artifact'], selected.artifact);
      expect(update.guide['revision'], 12);
    },
  );

  test('Recovery update starts on the permanent-pair image and selects the recovery CORE build', () {
    final update = session(
      snapshot: File('assets/bench/claimed-firmware-update.v11.json')
          .readAsStringSync(),
    );
    final previous = BenchDefinition.fromSnapshot(
      File(BenchDefinition.pairedAsset).readAsStringSync(),
    );
    final next = BenchDefinition.fromSnapshot(
      File(BenchDefinition.recoveryAsset).readAsStringSync(),
    );
    final expected = next.builds.singleWhere((b) => b.role == 'Core');
    expect(
      update.guide['before_source'],
      previous.builds.singleWhere((b) => b.role == 'Core').source,
    );
    expect(update.guide['after_source'], expected.source);
    expect(update.guide['after_artifact'], expected.artifact);
    expect(next.runnerFiles, contains('tools/connection_recovery.py'));
  });

  test('Supervised permanent-pair CORE update starts at the RTC2 image', () {
    final snapshot = File('assets/bench/claimed-firmware-update.v10.json')
        .readAsStringSync();
    final update = session(snapshot: snapshot);
    final previous = BenchDefinition.fromSnapshot(
      File(BenchDefinition.rtc2Asset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    final next = BenchDefinition.fromSnapshot(
      File(BenchDefinition.pairedAsset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    expect(update.guide['revision'], 10);
    expect(update.guide['before_source'], previous.source);
    expect(update.guide['after_source'], next.source);
    expect(update.guide['after_artifact'], next.artifact);
    expect(
      () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
      throwsFormatException,
    );
  });
  test(
    'Controlled RTC2 idle CORE update binds the prior source and exact image',
    () {
      final snapshot = File('assets/bench/claimed-firmware-update.v9.json')
          .readAsStringSync();
      final update = session(snapshot: snapshot);
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.legacyRtc2Asset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      final next = BenchDefinition.fromSnapshot(
        File(BenchDefinition.rtc2Asset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      expect(update.guide['revision'], 9);
      expect(update.guide['before_source'], previous.source);
      expect(update.guide['after_source'], next.source);
      expect(update.guide['after_artifact'], next.artifact);
      expect(
        () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
        throwsFormatException,
      );
    },
  );
  test(
    'RTC2 observation CORE update binds the prior source and exact image',
    () {
      final snapshot = File('assets/bench/claimed-firmware-update.v8.json')
          .readAsStringSync();
      final update = session(snapshot: snapshot);
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.cryptoKeysAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      final next = BenchDefinition.fromSnapshot(
        File(BenchDefinition.legacyRtc2Asset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      expect(update.guide['revision'], 8);
      expect(update.guide['before_source'], previous.source);
      expect(update.guide['after_source'], next.source);
      expect(update.guide['after_artifact'], next.artifact);
      expect(
        () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
        throwsFormatException,
      );
    },
  );
  test('key lifecycle CORE update binds the prior source and exact image', () {
    final snapshot = File('assets/bench/claimed-firmware-update.v7.json')
        .readAsStringSync();
    final update = session(snapshot: snapshot);
    final previous = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoReentryAsset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    final next = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoKeysAsset).readAsStringSync(),
    ).builds.singleWhere((b) => b.role == 'Core');
    expect(update.guide['revision'], 7);
    expect(update.guide['before_source'], previous.source);
    expect(update.guide['after_source'], next.source);
    expect(update.guide['after_artifact'], next.artifact);
    expect(
      () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
      throwsFormatException,
    );
  });
  test(
    'reentry CORE update binds the prior verified source and exact new image',
    () {
      final snapshot = File('assets/bench/claimed-firmware-update.v6.json')
          .readAsStringSync();
      final update = session(snapshot: snapshot);
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.cryptoProbeAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      final next = BenchDefinition.fromSnapshot(
        File(BenchDefinition.cryptoReentryAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      expect(update.guide['revision'], 6);
      expect(update.guide['before_source'], previous.source);
      expect(update.guide['after_source'], next.source);
      expect(update.guide['after_artifact'], next.artifact);
      expect(
        () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
        throwsFormatException,
      );
    },
  );
  test(
    'C8.3 CORE update binds the previously tested source and exact probe image',
    () {
      final snapshot = File('assets/bench/claimed-firmware-update.v5.json')
          .readAsStringSync();
      final update = session(snapshot: snapshot);
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.startupDiagnosticsAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      final next = BenchDefinition.fromSnapshot(
        File(BenchDefinition.cryptoProbeAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      expect(update.guide['revision'], 5);
      expect(update.guide['before_source'], previous.source);
      expect(update.guide['after_source'], next.source);
      expect(update.guide['after_artifact'], next.artifact);
      expect(
        () => session(snapshot: snapshot.replaceFirst(next.artifact, '0' * 64)),
        throwsFormatException,
      );
    },
  );

  test(
    'C8.3 CORE update requires confirmation and verifies both builds',
    () async {
      final previous = BenchDefinition.fromSnapshot(
        File(BenchDefinition.startupDiagnosticsAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      final next = BenchDefinition.fromSnapshot(
        File(BenchDefinition.cryptoProbeAsset).readAsStringSync(),
      ).builds.singleWhere((b) => b.role == 'Core');
      bootBeforeSource = previous.source;
      runner.buildSource = next.source;
      runner.buildArtifact = next.artifact;
      final s = session(
        snapshot: File('assets/bench/claimed-firmware-update.v5.json')
            .readAsStringSync(),
      );
      await s.preflight(operatorReady: true);
      expect(s.phase, 'awaiting_bootloader');
      runner.mode = 'bootloader';
      await expectLater(s.install(confirmed: false), throwsStateError);
      expect(runner.commands.where((command) => command == 'install'), isEmpty);
      await s.install(confirmed: true);
      expect(s.phase, 'verified');
      expect(calls, [previous.source, next.source]);
      expect(runner.commands, ['inventory', 'inventory', 'install']);
    },
  );

  test('claimed CORE update retains intent and verifies both identities without provisioning', () async {
    final s = session();
    await s.preflight(operatorReady: true);
    expect(s.phase, 'awaiting_bootloader');
    runner.mode = 'bootloader';
    await s.install(confirmed: true);
    expect(s.phase, 'verified');
    expect(calls, [oldSource, newSource]);
    expect(runner.commands, ['inventory', 'inventory', 'install']);
    expect(gateway.authorizations, 3);
    final records = temp
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.contains('firmware-updates'))
        .toList();
    expect(records.length, 5);
    final phases = records
        .map(
          (f) => (jsonDecode(f.readAsStringSync())['record'] as Map)['phase'],
        )
        .toSet();
    expect(
      phases,
      containsAll([
        'preflight',
        'awaiting_bootloader',
        'write_started',
        'awaiting_postflight',
        'verified',
      ]),
    );
  });

  test('changed ownership, missing key and unavailable application target block before writing', () async {
    gateway.selected = deviceJson(owner: otherAccount);
    await expectLater(
      session().preflight(operatorReady: true),
      throwsFormatException,
    );
    gateway.selected = deviceJson();
    gateway.missingKey = true;
    await expectLater(
      session().preflight(operatorReady: true),
      throwsFormatException,
    );
    gateway.missingKey = false;
    runner.noTarget = true;
    await expectLater(
      session().preflight(operatorReady: true),
      throwsFormatException,
    );
    expect(runner.commands.where((x) => x == 'install'), isEmpty);
  });

  test(
    'operator can cancel safely before writing; failed proof releases lock',
    () async {
      final s = session();
      await s.preflight(operatorReady: true);
      await s.cancelBeforeWrite();
      expect(s.phase, 'cancelled_before_write');
      proofFails = true;
      await expectLater(
        session().preflight(operatorReady: true),
        throwsFormatException,
      );
      proofFails = false;
      await session().preflight(operatorReady: true);
      expect(runner.commands.where((x) => x == 'install'), isEmpty);
    },
  );

  test('missing bootloader, unqualified build or unconfirmed selection cannot write', () async {
    final s = session();
    await s.preflight(operatorReady: true);
    await expectLater(s.install(confirmed: false), throwsStateError);
    await expectLater(s.install(confirmed: true), throwsFormatException);
    runner.mode = 'bootloader';
    runner.noBuild = true;
    await expectLater(s.install(confirmed: true), throwsFormatException);
    expect(runner.commands.where((x) => x == 'install'), isEmpty);
    await s.cancelBeforeWrite();
  });

  test(
    'an interrupted write is durable and blocks another operator attempt',
    () async {
      final s = session();
      await s.preflight(operatorReady: true);
      runner.mode = 'bootloader';
      runner.installFailure = StateError('connection lost');
      await expectLater(s.install(confirmed: true), throwsStateError);
      expect(s.phase, 'interrupted_after_write');
      runner.mode = 'app';
      runner.installFailure = null;
      await expectLater(
        session().preflight(operatorReady: true),
        throwsA(anything),
      );
      expect(runner.commands.where((x) => x == 'install').length, 1);
    },
  );

  test('changed install evidence, failed post-proof and unchanged boot stay unresolved', () async {
    for (final scenario in ['install', 'proof', 'boot']) {
      await temp.delete(recursive: true);
      temp = await Directory.systemTemp.createTemp('claimed-update-test-');
      store = EvidenceJournal(temp);
      runner = Runner();
      sameBoot = false;
      postProofFails = false;
      final s = session();
      await s.preflight(operatorReady: true);
      runner.mode = 'bootloader';
      runner.badInstall = scenario == 'install';
      postProofFails = scenario == 'proof';
      sameBoot = scenario == 'boot';
      await expectLater(s.install(confirmed: true), throwsFormatException);
      expect(s.phase, 'interrupted_after_write');
    }
  });

  test(
    'durable history rejects conflicting generations and altered bindings',
    () async {
      final s = session();
      await s.preflight(operatorReady: true);
      final report = Map<String, dynamic>.from(s.report!);
      await store.saveUpdate(report); // exact replay is idempotent
      await expectLater(
        store.saveUpdate({...report, 'serial': 'D999999999999'}),
        throwsFormatException,
      );
      final next = {...report, 'generation': 3, 'phase': 'write_started'};
      await expectLater(
        store.saveUpdate({...next, 'owner_id': otherAccount}),
        throwsFormatException,
      );
      await expectLater(
        store.saveUpdate({...next, 'phase': 'verified'}),
        throwsFormatException,
      );
      await expectLater(store.releaseUpdate(next), throwsFormatException);
      final other = {
        ...report,
        'account': otherAccount,
        'id': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        'generation': 1,
        'phase': 'preflight',
      };
      await expectLater(
        store.beginUpdate(other),
        throwsA(isA<FileSystemException>()),
      );
      await s.cancelBeforeWrite();
    },
  );

  test(
    'repeat starts and cancellation outside the preflight phase are refused',
    () async {
      final s = session();
      await expectLater(s.cancelBeforeWrite(), throwsStateError);
      await s.preflight(operatorReady: true);
      await expectLater(s.preflight(operatorReady: true), throwsStateError);
      await s.cancelBeforeWrite();
    },
  );

  test(
    'restart finds unresolved evidence and refuses another account',
    () async {
      final first = session();
      expect(await first.checkPending(), isFalse);
      await first.preflight(operatorReady: true);
      runner.mode = 'bootloader';
      runner.installFailure = StateError('interrupted');
      await expectLater(first.install(confirmed: true), throwsStateError);
      final restarted = session();
      expect(await restarted.checkPending(), isTrue);
      expect(restarted.phase, 'review_required');
      final retained = await restarted.export(temp.path);
      expect(await File(retained).exists(), isTrue);
      await expectLater(restarted.install(confirmed: true), throwsStateError);
      await expectLater(
        store.pendingUpdate(otherAccount, hardware),
        throwsFormatException,
      );
    },
  );

  test(
    'corrupt or missing update evidence remains blocked for review',
    () async {
      final first = session();
      await first.preflight(operatorReady: true);
      final records = temp
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.contains('firmware-updates'))
          .toList();
      final latest = records.firstWhere((f) => f.path.endsWith('/2.json'));
      await latest.writeAsString('{"record":{},"sha256":"invalid"}');
      await expectLater(session().checkPending(), throwsFormatException);
      await latest.delete();
      final firstFile = records.firstWhere((f) => f.path.endsWith('/1.json'));
      await firstFile.delete();
      await expectLater(session().checkPending(), throwsFormatException);
    },
  );

  test(
    'missing operator access and altered guide block the workflow',
    () async {
      expect(() => session(snapshot: 'modified'), throwsFormatException);
      gateway.denied = true;
      await expectLater(
        session().preflight(operatorReady: true),
        throwsA(isA<OperatorDenied>()),
      );
      gateway.denied = false;
      current = false;
      await expectLater(
        session().preflight(operatorReady: true),
        throwsA(isA<SessionExpired>()),
      );
      expect(runner.commands, isEmpty);
    },
  );
  test(
    'preflight requires explicit stopped and saved-work confirmation',
    () async {
      final s = session();
      await expectLater(s.preflight(operatorReady: false), throwsStateError);
      expect(runner.commands, isEmpty);
      expect(gateway.authorizations, 0);
    },
  );
  test(
    'preflight blocks if the exact qualified image is unavailable',
    () async {
      runner.noBuild = true;
      await expectLater(
        session().preflight(operatorReady: true),
        throwsFormatException,
      );
      expect(calls, isEmpty);
      expect(runner.commands, ['inventory']);
    },
  );

  test('device update lock also protects a second environment', () async {
    final s = session();
    await s.preflight(operatorReady: true);
    final alternate = EvidenceJournal(
      Directory('${temp.path}/other-environment'),
      updateLocks: Directory('${temp.path}/update-locks'),
    );
    final record = {
      ...s.report!,
      'account': otherAccount,
      'id': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'generation': 1,
      'phase': 'preflight',
    };
    await expectLater(
      alternate.beginUpdate(record),
      throwsA(isA<FileSystemException>()),
    );
    await s.cancelBeforeWrite();
  });
  test(
    'private report export verifies durable bytes and rejects invalid folders',
    () async {
      final s = session();
      await expectLater(s.export(temp.path), throwsStateError);
      await s.preflight(operatorReady: true);
      await expectLater(
        s.export('relative'),
        throwsA(isA<FileSystemException>()),
      );
      final path = await s.export(temp.path);
      expect(await File(path).exists(), isTrue);
      expect(await s.export(temp.path), path);
      final envelope = jsonDecode(await File(path).readAsString()) as Map;
      expect((envelope['record'] as Map)['phase'], 'awaiting_bootloader');
      final records = temp
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.contains('firmware-updates'))
          .toList();
      final latest = records.firstWhere((f) => f.path.endsWith('/2.json'));
      await latest.writeAsString('damaged');
      await expectLater(s.export(temp.path), throwsFormatException);
    },
  );
  test(
    'a failed intent flush blocks the firmware write and any retry',
    () async {
      store = EvidenceJournal(temp, flushUpdateIntent: () async => false);
      final s = session();
      await s.preflight(operatorReady: true);
      runner.mode = 'bootloader';
      await expectLater(
        s.install(confirmed: true),
        throwsA(isA<FileSystemException>()),
      );
      expect(runner.commands.where((x) => x == 'install'), isEmpty);
      await expectLater(
        store.saveUpdate(s.report!),
        throwsA(isA<FileSystemException>()),
      );
      final restarted = session();
      expect(await restarted.checkPending(), isTrue);
      expect(restarted.phase, 'review_required');
    },
  );
  test('ownership changes after proof stop installation', () async {
    final s = session();
    await s.preflight(operatorReady: true);
    gateway.selected = deviceJson(owner: otherAccount);
    runner.mode = 'bootloader';
    await expectLater(s.install(confirmed: true), throwsFormatException);
    expect(runner.commands.where((x) => x == 'install'), isEmpty);
  });
  test('changed proof binding and sign-out stop before any write', () async {
    Future<Json> wrongProof(
      String account,
      Json selection,
      BenchDefinition _,
    ) async => {
      ...selection,
      'build': '0' * 64,
      'state': 'ready',
      'busy': false,
      'failed': false,
      'public_key': key,
      'boot': 'a' * 32,
      'challenge': 'c' * 64,
      'signature': 'd' * 128,
    };
    final invalid = ClaimedUpdateSession(
      account: account,
      device: device,
      article: article,
      gateway: gateway,
      runner: runner,
      prove: wrongProof,
      store: store,
      definition: definition,
      guideSnapshot: guide,
      newId: () => 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      now: () => DateTime.utc(2026),
      workshopFingerprint: () async => 'f' * 64,
      current: () => current,
    );
    await expectLater(
      invalid.preflight(operatorReady: true),
      throwsFormatException,
    );
    expect(invalid.phase, 'preflight_failed');
    Future<Json> signedOut(
      String account,
      Json selection,
      BenchDefinition d,
    ) async {
      final frame = await proof(account, selection, d);
      current = false;
      return frame;
    }

    final interrupted = ClaimedUpdateSession(
      account: account,
      device: device,
      article: article,
      gateway: gateway,
      runner: runner,
      prove: signedOut,
      store: store,
      definition: definition,
      guideSnapshot: guide,
      newId: () => 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      now: () => DateTime.utc(2026),
      workshopFingerprint: () async => 'f' * 64,
      current: () => current,
    );
    await expectLater(
      interrupted.preflight(operatorReady: true),
      throwsA(isA<SessionExpired>()),
    );
    expect(runner.commands.where((x) => x == 'install'), isEmpty);
  });
}
