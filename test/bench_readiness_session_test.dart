import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';

import 'bench_session_test.dart' as base;
import 'widget_test.dart' as fixtures;

void main() {
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
      await session.observe('empty');
      expect(session.report!['steps'][4]['status'], 'Passed');
      expect(session.report!['steps'][5]['status'], 'Passed');
      await session.export('/synthetic');
      expect(session.report!['outcome'], 'Passed');
      final saved = await f.store.reopenBench(
        fixtures.actor,
        session.report!['id'],
      );
      expect(saved['definition_sha256'], BenchDefinition.readinessDigest);
      session.selectDefinition(identity);
      await session.open(saved['id']);
      expect(
        session.report!['definition_sha256'],
        BenchDefinition.readinessDigest,
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
