import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'bench_session_test.dart' as base;
import 'widget_test.dart' as fixtures;

void main() {
  test(
    'claimed device retains an independently comparable owner reference',
    () async {
      final identity = BenchDefinition.fromSnapshot(
        File(BenchDefinition.asset).readAsStringSync(),
      );
      final readiness = BenchDefinition.fromSnapshot(
        File(BenchDefinition.readinessAsset).readAsStringSync(),
      );
      final fixture = base.BenchFixture(base.TestBenchStore(), identity);
      await fixture.init();
      fixture.readiness = readiness;
      var reads = 0;
      fixture.readinessReader =
          (account, selection, key, {onDiagnostic}) async => {
            'state': 'empty',
            'boot': ++reads == 1 ? 'aa' * 16 : 'bb' * 16,
          };
      final original = fixture.registry.devices.single;
      final claimed = DeviceRecord.fromJson({
        'id': original.id,
        'serial': original.serial,
        'article_revision_id': original.revisionId,
        'provisioning_state': original.state,
        'hardware_uid': original.hardwareUid,
        'owner_user_id': 'synthetic-owner',
      });
      final session = fixture.session();
      session.selectDefinition(readiness);
      await session.start(claimed, fixture.registry.articles.single);
      await session.connected(claimed, fixture.registry.articles.single);
      await session.checkAfterRestart(confirmed: true);
      final registry =
          session.report!['steps'][4]['evidence']['registry_check'];
      expect(registry['claimed'], true);
      expect(registry['owner_sha256'], benchHash('synthetic-owner'));
    },
  );
  for (final state in ['pending', 'ready']) {
    test('read-only $state baseline and fresh boot are compared', () async {
      final identity = BenchDefinition.fromSnapshot(
        File(BenchDefinition.asset).readAsStringSync(),
      );
      final readiness = BenchDefinition.fromSnapshot(
        File(BenchDefinition.readinessAsset).readAsStringSync(),
      );
      final fixture = base.BenchFixture(base.TestBenchStore(), identity);
      await fixture.init();
      fixture.readiness = readiness;
      var reads = 0;
      fixture.readinessReader =
          (account, selection, key, {onDiagnostic}) async => {
            'state': state,
            'boot': ++reads == 1 ? 'aa' * 16 : 'bb' * 16,
            'revision': state == 'ready' ? 1 : 0,
            'content_id': state == 'ready' ? 'cc' * 32 : '',
          };
      final session = fixture.session();
      session.selectDefinition(readiness);
      await fixture.start(session);
      await fixture.connected(session);
      await session.checkAfterRestart(confirmed: true);
      expect(reads, 2);
      expect(fixture.credentials, 0);
      expect(fixture.deliveryReads, 0);
      expect(session.report!['steps'][4]['status'], 'Passed');
      expect(
        session.report!['steps'][4]['evidence']['registry_check']['matched'],
        true,
      );
    });
  }
  test(
    'readiness saves first, records an observation and reopens the report',
    () async {
      final identity = BenchDefinition.fromSnapshot(
        File(BenchDefinition.asset).readAsStringSync(),
      );
      final inspection = BenchDefinition.fromSnapshot(
        File(BenchDefinition.readinessAsset).readAsStringSync(),
      );
      final f = base.BenchFixture(base.TestBenchStore(), identity);
      await f.init();
      var reads = 0;
      final session = BenchSession(
        fixtures.actor,
        identity,
        f.store,
        (account, definition) async =>
            f.usbRunner.execute(account: account, command: 'inventory'),
        f.usbRunner.cancel,
        (account, selection, {onDiagnostic}) async =>
            throw StateError('Identity guide must not run'),
        () async => 'a' * 64,
        () => '90510000-0000-4000-8000-000000000001',
        () => DateTime.utc(2026, 11, 22),
        readinessDefinition: inspection,
        lookupPublicKey: (device, article) async => '04${'11' * 64}',
        readReadiness: (account, selection, publicKey, {onDiagnostic}) async {
          expect(f.store.records, isNotEmpty);
          expect(publicKey, '04${'11' * 64}');
          reads++;
          onDiagnostic?.call({'diagnostic': 'synthetic'});
          return <String, dynamic>{
            'state': 'empty',
            'boot': reads == 1 ? 'aa' * 16 : 'bb' * 16,
            'inspection': {'state': 'blank', 'sha256': '22' * 32},
          };
        },
      );
      session.selectDefinition(inspection);
      final device = f.registry.devices.single,
          article = f.registry.articles.single;
      await session.start(device, article);
      expect(session.report!['steps'][1]['status'], 'Passed');
      await session.connected(device, article);
      expect(reads, 1);
      expect(
        session.report!['steps'][3]['evidence']['frame']['state'],
        'empty',
      );
      await session.checkAfterRestart(confirmed: true);
      expect(session.report!['steps'][4]['status'], 'Passed');
      expect(session.report!['steps'][5]['status'], 'Passed');
      await session.export('/synthetic');
      expect(session.report!['outcome'], 'Passed');
      final saved = await f.store.reopenBench(
        fixtures.actor,
        session.report!['id'],
      );
      expect(saved['definition_sha256'], BenchDefinition.readinessV2Digest);
      session.selectDefinition(identity);
      await session.open(saved['id']);
      expect(
        session.report!['definition_sha256'],
        BenchDefinition.readinessV2Digest,
      );
    },
  );

  test('missing key evidence blocks before the readiness runner', () async {
    final identity = BenchDefinition.fromSnapshot(
      File(BenchDefinition.asset).readAsStringSync(),
    );
    final inspection = BenchDefinition.fromSnapshot(
      File(BenchDefinition.readinessAsset).readAsStringSync(),
    );
    final f = base.BenchFixture(base.TestBenchStore(), identity);
    await f.init();
    var reads = 0;
    final session = BenchSession(
      fixtures.actor,
      identity,
      f.store,
      (account, definition) async =>
          f.usbRunner.execute(account: account, command: 'inventory'),
      f.usbRunner.cancel,
      (account, selection, {onDiagnostic}) async => <String, dynamic>{},
      () async => 'a' * 64,
      () => '90510000-0000-4000-8000-000000000002',
      () => DateTime.utc(2026, 11, 22),
      readinessDefinition: inspection,
      lookupPublicKey: (device, article) async =>
          throw const FormatException('missing'),
      readReadiness: (account, selection, key, {onDiagnostic}) async {
        reads++;
        return <String, dynamic>{};
      },
    );
    session.selectDefinition(inspection);
    await session.start(f.registry.devices.single, f.registry.articles.single);
    await session.connected(
      f.registry.devices.single,
      f.registry.articles.single,
    );
    expect(reads, 0);
    expect(session.report!['outcome'], 'Blocked');
    expect(session.report!['steps'][4]['status'], 'Not run');
  });

  test('readiness without an owner runner is blocked and an active guide cannot change', () async {
    final identity = BenchDefinition.fromSnapshot(
      File(BenchDefinition.asset).readAsStringSync(),
    );
    final inspection = BenchDefinition.fromSnapshot(
      File(BenchDefinition.readinessAsset).readAsStringSync(),
    );
    final f = base.BenchFixture(base.TestBenchStore(), identity);
    await f.init();
    final session = BenchSession(
      fixtures.actor,
      identity,
      f.store,
      (account, definition) async =>
          f.usbRunner.execute(account: account, command: 'inventory'),
      f.usbRunner.cancel,
      (account, selection, {onDiagnostic}) async => <String, dynamic>{},
      () async => 'a' * 64,
      () => '90510000-0000-4000-8000-000000000003',
      () => DateTime.utc(2026, 11, 22),
      readinessDefinition: inspection,
    );
    expect(
      () => session.selectDefinition(
        BenchDefinition.fromSnapshot(identity.snapshot),
      ),
      throwsStateError,
    );
    session.selectDefinition(inspection);
    await session.start(f.registry.devices.single, f.registry.articles.single);
    expect(() => session.selectDefinition(identity), throwsStateError);
    await session.connected(
      f.registry.devices.single,
      f.registry.articles.single,
    );
    expect(session.report!['outcome'], 'Blocked');
  });
}
