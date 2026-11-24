import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'support/bench_fixture.dart' as base;
import 'widget_test.dart' as fixtures;

void main() {
  late BenchDefinition identity, diagnostics;
  late base.BenchFixture fixture;
  setUp(() async {
    identity = BenchDefinition.fromSnapshot(
      File(BenchDefinition.asset).readAsStringSync(),
    );
    diagnostics = BenchDefinition.fromSnapshot(
      File(BenchDefinition.startupDiagnosticsAsset).readAsStringSync(),
    );
    fixture = base.BenchFixture(base.TestBenchStore(), identity);
    await fixture.init();
  });

  BenchSession session({
    required StartupDiagnosticsReader reader,
    Future<String> Function(DeviceRecord, ArticleRevision)? key,
  }) => BenchSession(
    fixtures.actor,
    identity,
    fixture.store,
    (account, definition) =>
        fixture.usbRunner.execute(account: account, command: 'inventory'),
    fixture.usbRunner.cancel,
    (account, selection, {onDiagnostic}) async => {},
    () async => 'a' * 64,
    () => '90510000-0000-4000-8000-000000000001',
    () => DateTime.utc(2026, 11, 24),
    startupDiagnosticsDefinition: diagnostics,
    readStartupDiagnostics: reader,
    lookupPublicKey: key ?? (device, article) async => '04${'11' * 64}',
  )..selectDefinition(diagnostics);

  test('selection is durable before USB and pass is reviewed, reopened and exported', () async {
    var calls = 0, lookups = 0;
    final s = session(
      key: (d, a) async {
        lookups++;
        return '04${'11' * 64}';
      },
      reader: (account, selection, key, check, {onDiagnostic}) async {
        calls++;
        expect(fixture.store.records, isNotEmpty);
        expect(check, 'radio');
        onDiagnostic?.call({'diagnostic': 'synthetic'});
        return {
          'outcome': 'passed',
          'selection': check,
          'frame': {'results': []},
        };
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await s.start(d, a, startupCheck: 'radio');
    expect(s.report!['startup_check'], 'radio');
    await s.connected(d, a);
    expect(calls, 1);
    expect(lookups, 2);
    expect(s.report!['steps'][3]['status'], 'Passed');
    await s.reviewStartupResults();
    expect(s.report!['steps'][4]['evidence']['reviewed'], true);
    expect(s.report!['steps'][5]['status'], 'Passed');
    await s.export('/synthetic');
    expect(s.report!['outcome'], 'Passed');
    final saved = await fixture.store.reopenBench(
      fixtures.actor,
      s.report!['id'],
    );
    expect(saved['startup_check'], 'radio');
    expect(
      saved['definition_sha256'],
      BenchDefinition.startupDiagnosticsDigest,
    );
  });

  test('failed measured checks and diagnostics stay in the failed report', () async {
    final s = session(
      reader: (account, selection, key, check, {onDiagnostic}) async {
        onDiagnostic?.call({'partial': 'retained'});
        return {
          'outcome': 'failed',
          'selection': check,
          'frame': {
            'run_id': 1,
            'results': [
              {'id': 'radio', 'result': 'unavailable'},
            ],
          },
        };
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await s.start(d, a);
    await s.connected(d, a);
    expect(s.report!['outcome'], 'Failed');
    expect(
      s.report!['steps'][3]['evidence']['frame']['frame']['results'][0]['result'],
      'unavailable',
    );
    expect(s.report!['artifacts'], isNotEmpty);
  });

  test('changed or unavailable registry after measurement prevents acceptance and keeps frame', () async {
    for (final unavailable in [false, true]) {
      var count = 0;
      final s = session(
        key: (d, a) async {
          count++;
          if (count == 2 && unavailable) {
            throw const FormatException('registry unavailable');
          }
          return count == 2 ? 'changed' : 'key';
        },
        reader: (account, selection, key, check, {onDiagnostic}) async => {
          'outcome': 'passed',
          'frame': {'run_id': 1},
        },
      );
      final d = fixture.registry.devices.single,
          a = fixture.registry.articles.single;
      await s.start(d, a);
      await s.connected(d, a);
      expect(s.report!['outcome'], 'Failed');
      expect(s.report!['steps'][3]['evidence']['frame']['frame']['run_id'], 1);
    }
  });

  test('missing runner and unknown selection stop before USB', () async {
    var reads = 0;
    final s = session(
      reader: (account, selection, key, check, {onDiagnostic}) async {
        reads++;
        return {};
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await expectLater(
      s.start(d, a, startupCheck: 'bad'),
      throwsFormatException,
    );
    expect(reads, 0);
    expect(fixture.store.records, isEmpty);
  });
  test('failed local save blocks discovery and runner', () async {
    fixture.store.failGeneration = 1;
    var calls = 0;
    final s = session(
      reader: (account, selection, key, check, {onDiagnostic}) async {
        calls++;
        return {};
      },
    );
    await expectLater(
      s.start(
        fixture.registry.devices.single,
        fixture.registry.articles.single,
      ),
      throwsA(isA<FileSystemException>()),
    );
    expect(calls, 0);
    expect(s.pending, isNotNull);
  });

  test('cancellation retains late measurements and never passes', () async {
    final entered = Completer<void>(), release = Completer<void>();
    final s = session(
      reader: (account, selection, key, check, {onDiagnostic}) async {
        entered.complete();
        await release.future;
        onDiagnostic?.call({'partial': 'retained'});
        return {
          'outcome': 'passed',
          'frame': {'run_id': 1},
        };
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await s.start(d, a);
    final running = s.perform(() => s.connected(d, a));
    await entered.future;
    final stopped = s.stop('Operator cancelled');
    release.complete();
    await running;
    await stopped;
    expect(s.report!['outcome'], 'Cancelled');
    expect(s.report!['steps'][3]['status'], 'Incomplete');
    expect(
      s.report!['steps'][3]['evidence']['late_result']['frame']['frame']['run_id'],
      1,
    );
    expect(s.report!['artifacts'], isNotEmpty);
  });
  test('claimed ownership is recorded as a comparable digest', () async {
    final original = fixture.registry.devices.single;
    final claimed = DeviceRecord.fromJson({
      'id': original.id,
      'serial': original.serial,
      'article_revision_id': original.revisionId,
      'provisioning_state': original.state,
      'hardware_uid': original.hardwareUid,
      'owner_user_id': 'synthetic-owner',
    });
    final s = session(
      reader: (account, selection, key, check, {onDiagnostic}) async => {
        'outcome': 'passed',
      },
    );
    await s.start(claimed, fixture.registry.articles.single);
    await s.connected(claimed, fixture.registry.articles.single);
    final check = s.report!['steps'][3]['evidence']['registry_check'];
    expect(check['claimed'], true);
    expect(check['owner_sha256'], benchHash('synthetic-owner'));
  });
  test('missing registry binding blocks before USB diagnostics', () async {
    var reads = 0;
    final s = session(
      key: (device, article) async =>
          throw const FormatException('missing identity'),
      reader: (account, selection, key, check, {onDiagnostic}) async {
        reads++;
        return {};
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await s.start(d, a);
    await s.connected(d, a);
    expect(reads, 0);
    expect(s.report!['outcome'], 'Blocked');
  });

  test(
    'expired or denied access interrupts and retains measured data',
    () async {
      for (final error in [SessionExpired(), OperatorDenied()]) {
        var count = 0;
        final s = session(
          key: (d, a) async {
            if (++count == 2) throw error;
            return 'key';
          },
          reader: (account, selection, key, check, {onDiagnostic}) async => {
            'outcome': 'passed',
            'frame': {'run_id': 1},
          },
        );
        final d = fixture.registry.devices.single,
            a = fixture.registry.articles.single;
        await s.start(d, a);
        await expectLater(s.connected(d, a), throwsA(same(error)));
        expect(s.report!['outcome'], 'Interrupted');
        expect(s.report!['steps'][3]['status'], 'Incomplete');
        expect(
          s.report!['steps'][3]['evidence']['frame']['frame']['run_id'],
          1,
        );
        expect(
          s.report!['steps'][3]['evidence']['error'],
          'Operator access is no longer available.',
        );
      }
    },
  );
}
