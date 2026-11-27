import 'dart:io';
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'support/bench_fixture.dart';
import 'widget_test.dart' as fixtures;

void main() {
  final guide = BenchDefinition.fromSnapshot(
    File(BenchDefinition.pairedAsset).readAsStringSync(),
  );
  final recovery = BenchDefinition.fromSnapshot(
    File(BenchDefinition.recoveryAsset).readAsStringSync(),
  );
  final devices = <String, DeviceRecord>{};
  final articles = <String, ArticleRevision>{};
  final hardware = {'Link': '1234567800000001', 'Core': '1234567800000002'};
  for (final (i, role) in ['Link', 'Core'].indexed) {
    final id = 'a2000000-0000-4000-8000-00000000000${i + 1}';
    articles[role] = ArticleRevision.fromJson({
      'id': id,
      'article_id': id,
      'role': role,
      'code': role,
      'name': role,
      'revision': 1,
      'case_version': '1',
      'parts': <Json>[],
    });
    devices[role] = DeviceRecord.fromJson({
      'id': 'a3000000-0000-4000-8000-00000000000${i + 1}',
      'serial': 'D00000000000${i + 1}',
      'article_revision_id': id,
      'provisioning_state': 'provisioned',
      'hardware_uid': hardware[role],
    });
  }
  late TestBenchStore store;
  late BenchSession session;
  late String fault;
  late int ids;
  late Completer<void> started, cancelled;
  setUp(() {
    store = TestBenchStore();
    ids = 0;
    started = Completer<void>();
    cancelled = Completer<void>();
    fault = '';
    session = BenchSession(
      fixtures.actor,
      guide,
      store,
      (account, definition) async => {
        'targets': [
          for (final r in hardware.keys)
            {'mode': 'app', 'label': r, 'hardware': hardware[r]},
        ],
        'builds': <Json>[],
      },
      () async {
        if (!cancelled.isCompleted) cancelled.complete();
      },
      (a, read, {onDiagnostic}) async => {},
      () async => 'a' * 64,
      () => '90510000-0000-4000-8000-${(++ids).toString().padLeft(12, '0')}',
      () => DateTime.utc(2026, 11, 27),
      recoveryDefinition: recovery,
      lookupPublicKey: (device, article) async => '04${'22' * 64}',
      readPair: (account, peers, {onDiagnostic}) async {
        onDiagnostic?.call({'phase': 'synthetic USB progress'});
        if (fault == 'cancel') {
          started.complete();
          await cancelled.future;
          throw StateError('USB interrupted');
        }
        expect(store.records.length, 2);
        expect(
          store.records.values.map((r) => r['steps'][2]['status']),
          everyElement('Passed'),
        );
        return {
          for (final role in peers.keys)
            role: {
              'attempt': fault == 'attempt' && role == 'Core'
                  ? 'different'
                  : '5931abc4-b8ad-4117-b9d7-9f476a8b0e54',
              'peer_device_id': devices[role == 'Core' ? 'Link' : 'Core']!.id,
              'handshake': 'confirmed',
              'resources': {'role': role},
              if (session.definition == recovery) ...{
                'recovery_cases': ['cancel', 'stale'],
                'usb_minimum_free_bytes': role == 'Link' ? 2080 : 2152,
              },
              'exchange_sha256': 'b' * 64,
            },
        };
      },
    );
  });
  Future<void> runPair() async {
    await session.start(devices['Link']!, articles['Link']!);
    await session.connectPair(
      devices['Link']!,
      articles['Link']!,
      devices['Core']!,
      articles['Core']!,
    );
  }

  test(
    'separate durable board reports share the exchange and both export',
    () async {
      await runPair();
      expect(session.next, 5);
      await session.reviewStartupResults();
      await session.export('/synthetic');
      expect(
        store.records.values.map((r) => r['outcome']),
        everyElement('Passed'),
      );
      for (final r in store.records.values) {
        final other =
            store.records[r['steps'][2]['evidence']['supervised_peer_report']]!;
        expect(
          r['steps'][3]['evidence']['peer_device_id'],
          other['device']['id'],
        );
        expect(
          r['steps'][3]['evidence']['resources']['role'],
          r['device']['role'],
        );
        expect(r['exports'], hasLength(1));
      }
    },
  );
  test(
    'an interrupted measurement retains diagnostics for both boards',
    () async {
      fault = 'cancel';
      final operation = expectLater(
        session.perform(runPair),
        throwsA(anything),
      );
      await started.future;
      await session.stop('Operator cancelled');
      await operation;
      for (final r in store.records.values) {
        expect(r['outcome'], 'Cancelled');
        expect(
          r['artifacts'].single['content'],
          contains('synthetic USB progress'),
        );
      }
    },
  );
  test(
    'paired export reopens both reviewed records after Workshop closes',
    () async {
      await runPair();
      await session.reviewStartupResults();
      final current = session.report!['id'] as String;
      await session.stop('Workshop closed');
      await session.open(current);
      await session.export('/synthetic');
      expect(
        store.records.values.map((r) => r['outcome']),
        everyElement('Passed'),
      );
    },
  );
  test(
    'recovery saves both measured stack minima on each exported record',
    () async {
      session.selectDefinition(recovery);
      await runPair();
      await session.reviewStartupResults();
      await session.export('/synthetic');
      for (final r in store.records.values) {
        final evidence = r['steps'][3]['evidence'];
        expect(evidence['usb_minimum_by_role'], {'Link': 2080, 'Core': 2152});
        expect(evidence['recovery_cases'], ['cancel', 'stale']);
        expect(r['exports'], hasLength(1));
      }
    },
  );
  test('different attempts leave both records incomplete', () async {
    fault = 'attempt';
    await expectLater(runPair(), throwsA(anything));
    expect(
      store.records.values.map((r) => r['outcome']),
      everyElement('Incomplete'),
    );
  });
  test('review refuses a companion report that changed on disk', () async {
    await runPair();
    final peer = store.records.values.singleWhere(
      (r) => r['device']['role'] == 'Core',
    );
    peer['steps'][3]['evidence']['exchange_sha256'] = 'd' * 64;
    await expectLater(session.reviewStartupResults(), throwsA(anything));
    expect(store.records.values.every((r) => r['exports'].isEmpty), isTrue);
  });
}
