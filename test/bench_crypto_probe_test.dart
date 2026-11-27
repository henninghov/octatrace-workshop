import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'support/bench_fixture.dart' as base;
import 'widget_test.dart' as fixtures;

void main() {
  late BenchDefinition identity, probe, reentry, keys, rtc2;
  late base.BenchFixture fixture;
  setUp(() async {
    identity = BenchDefinition.fromSnapshot(
      File(BenchDefinition.asset).readAsStringSync(),
    );
    probe = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoProbeAsset).readAsStringSync(),
    );
    reentry = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoReentryAsset).readAsStringSync(),
    );
    keys = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoKeysAsset).readAsStringSync(),
    );
    rtc2 = BenchDefinition.fromSnapshot(
      File(BenchDefinition.rtc2Asset).readAsStringSync(),
    );
    fixture = base.BenchFixture(base.TestBenchStore(), identity);
    await fixture.init();
  });

  BenchSession session({
    required InspectionReader reader,
    Future<String> Function(DeviceRecord, ArticleRevision)? key,
    bool reentryTest = false,
    bool keysTest = false,
    bool clockTest = false,
  }) =>
      BenchSession(
        fixtures.actor,
        identity,
        fixture.store,
        (account, definition) =>
            fixture.usbRunner.execute(account: account, command: 'inventory'),
        fixture.usbRunner.cancel,
        (account, selection, {onDiagnostic}) async => {},
        () async => 'a' * 64,
        () => '90510000-0000-4000-8000-000000000001',
        () => DateTime.utc(2026, 11, 25),
        cryptoProbeDefinition: probe,
        cryptoReentryDefinition: reentry,
        cryptoKeysDefinition: keys,
        readCryptoProbe: reader,
        rtc2Definition: rtc2,
        readRtc2: reader,
        lookupPublicKey: key ?? (device, article) async => '04${'11' * 64}',
      )..selectDefinition(
        clockTest
            ? rtc2
            : keysTest
            ? keys
            : reentryTest
            ? reentry
            : probe,
      );

  test(
    'RTC2 records the quick observation under its own version and reopens it',
    () async {
      final s = session(
        clockTest: true,
        reader: (account, read, key, {onDiagnostic}) async {
          expect(read.definition.snapshotDigest, rtc2.snapshotDigest);
          return {
            'outcome': 'passed',
            'frame': {'wait_path_observed': true},
          };
        },
      );
      final d = fixture.registry.devices.single,
          a = fixture.registry.articles.single;
      await s.start(d, a);
      await s.connected(d, a);
      expect(s.report!['steps'][3]['status'], 'Passed');
      await s.reviewStartupResults();
      await s.export('/synthetic');
      final reopened = await fixture.store.reopenBench(
        fixtures.actor,
        s.report!['id'],
      );
      expect(reopened['definition_sha256'], rtc2.snapshotDigest);
      expect(reopened['outcome'], 'Passed');
    },
  );

  test('key lifecycle attempt retains its definition and results', () async {
    final s = session(
      keysTest: true,
      reader: (account, read, key, {onDiagnostic}) async {
        expect(read.definition.snapshotDigest, keys.snapshotDigest);
        expect(fixture.store.records, isNotEmpty);
        return {
          'outcome': 'passed',
          'frame': {
            'identity_signature': true,
            'agreement': true,
            'exhaustion': true,
            'stale_rejected': true,
            'cleaned': true,
            'stack_free_words': 777,
          },
        };
      },
    );
    final d = fixture.registry.devices.single,
        a = fixture.registry.articles.single;
    await s.start(d, a);
    await s.connected(d, a);
    expect(s.report!['steps'][3]['status'], 'Passed');
    await s.reviewStartupResults();
    await s.export('/synthetic');
    expect(s.report!['outcome'], 'Passed');
    expect(
      (await fixture.store.reopenBench(
        fixtures.actor,
        s.report!['id'],
      ))['definition_sha256'],
      keys.snapshotDigest,
    );
  });

  test(
    'reentry attempt retains its own immutable definition and evidence',
    () async {
      final s = session(
        reentryTest: true,
        reader: (account, read, key, {onDiagnostic}) async {
          expect(read.definition.snapshotDigest, reentry.snapshotDigest);
          expect(fixture.store.records, isNotEmpty);
          return {
            'outcome': 'passed',
            'frame': {
              'nested_refused': true,
              'outer_failed': true,
              'output_cleared': true,
              'input_intact': true,
              'later_hash': true,
              'stack_free_words': 777,
            },
          };
        },
      );
      final d = fixture.registry.devices.single,
          a = fixture.registry.articles.single;
      await s.start(d, a);
      await s.connected(d, a);
      expect(s.report!['steps'][3]['status'], 'Passed');
      await s.reviewStartupResults();
      await s.export('/synthetic');
      expect(s.report!['outcome'], 'Passed');
      expect(
        (await fixture.store.reopenBench(
          fixtures.actor,
          s.report!['id'],
        ))['definition_sha256'],
        reentry.snapshotDigest,
      );
    },
  );

  test(
    'saves before USB, then reviews, reopens and exports the measurement',
    () async {
      var lookups = 0;
      final s = session(
        key: (d, a) async {
          lookups++;
          return 'key';
        },
        reader: (account, read, key, {onDiagnostic}) async {
          expect(fixture.store.records, isNotEmpty);
          onDiagnostic?.call({'partial': 'retained'});
          return {
            'outcome': 'passed',
            'frame': {'run_id': 1, 'stack_free_words': 777},
          };
        },
      );
      final d = fixture.registry.devices.single,
          a = fixture.registry.articles.single;
      await s.start(d, a);
      await s.connected(d, a);
      expect(lookups, 2);
      expect(s.report!['steps'][3]['status'], 'Passed');
      await s.reviewStartupResults();
      await s.export('/synthetic');
      expect(s.report!['outcome'], 'Passed');
      expect(
        (await fixture.store.reopenBench(
          fixtures.actor,
          s.report!['id'],
        ))['definition_sha256'],
        probe.snapshotDigest,
      );
    },
  );

  test(
    'failed and interrupted work remain separate and retain partial evidence',
    () async {
      for (final outcome in ['failed', 'interrupted']) {
        final s = session(
          reader: (account, read, key, {onDiagnostic}) async {
            onDiagnostic?.call({'partial': 'retained'});
            return {
              'outcome': outcome,
              'frame': {'run_id': 4},
              'error': 'synthetic',
            };
          },
        );
        final d = fixture.registry.devices.single,
            a = fixture.registry.articles.single;
        await s.start(d, a);
        await s.connected(d, a);
        expect(
          s.report!['outcome'],
          outcome == 'failed' ? 'Failed' : 'Incomplete',
        );
        expect(
          s.report!['steps'][3]['evidence']['frame']['frame']['run_id'],
          4,
        );
        expect(s.report!['artifacts'], isNotEmpty);
      }
    },
  );

  test('unavailable or changed registry binding prevents a pass', () async {
    for (final unavailable in [false, true]) {
      var lookups = 0, reads = 0;
      final s = session(
        key: (d, a) async {
          lookups++;
          if (unavailable) throw const FormatException('missing key');
          return lookups == 1 ? 'key' : 'changed';
        },
        reader: (account, read, key, {onDiagnostic}) async {
          reads++;
          return {
            'outcome': 'passed',
            'frame': {'run_id': 2},
          };
        },
      );
      final d = fixture.registry.devices.single,
          a = fixture.registry.articles.single;
      await s.start(d, a);
      await s.connected(d, a);
      expect(s.report!['outcome'], unavailable ? 'Blocked' : 'Failed');
      expect(reads, unavailable ? 0 : 1);
    }
  });

  test('cancellation retains a late result and cannot pass', () async {
    final entered = Completer<void>(), release = Completer<void>();
    final s = session(
      reader: (account, read, key, {onDiagnostic}) async {
        entered.complete();
        await release.future;
        return {
          'outcome': 'passed',
          'frame': {'run_id': 3},
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
    expect(s.report!['outcome'], isNot('Passed'));
  });
}
