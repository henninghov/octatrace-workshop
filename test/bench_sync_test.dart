import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/bench_sync.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'support/bench_fixture.dart' show BenchFixture, TestBenchStore;
import 'widget_test.dart' as fixtures;

class BenchServer {
  final headers = <String, Json>{}, results = <String, Json>{};
  final objects = <String, String>{};
  final requests = <String>[];
  Json catalog = {};
  String? fault;
  Future<dynamic> call(String account, String name, Json p) async {
    expect(account, fixtures.actor);
    requests.add(name);
    switch (name) {
      case 'workshop_test_definitions':
        return [catalog];
      case 'workshop_submit_test_run':
        final h = p['p_header'] as Json, r = p['p_result'] as Json;
        headers[h['id']] = h;
        results[h['id']] = r;
        return fault == 'run' ? 0 : r['generation'];
      case 'workshop_test_artifacts':
        final refs = results[p['p_run']]!['artifacts'] as List;
        return fault == 'count'
            ? []
            : [
                for (final a in refs)
                  {
                    ...a,
                    'verified': objects.containsKey(a['sha256']),
                    if (fault == 'manifest') 'bytes': -1,
                  },
              ];
      case 'workshop_put_test_artifact':
        objects[p['p_sha256']] = p['p_base64'];
        return fault == 'put' ? 'wrong' : p['p_sha256'];
      case 'workshop_read_test_artifact':
        if (fault == 'offline') throw const SocketException('offline');
        return fault == 'read' ? 'wrong' : objects[p['p_sha256']];
      default:
        throw StateError(name);
    }
  }
}

void main() {
  final def = BenchDefinition.fromSnapshot(
    File(BenchDefinition.asset).readAsStringSync(),
  );
  late Directory dir;
  late EvidenceJournal files;
  late BenchFixture f;
  late BenchSession s;
  late BenchServer server;
  late BenchSync sync;
  setUp(() async {
    dir = await Directory.systemTemp.createTemp('bench-sync-');
    files = EvidenceJournal(dir);
    f = BenchFixture(TestBenchStore(files), def);
    await f.init();
    server = BenchServer()
      ..catalog = {
        'test_key': def.guide['key'],
        'revision': def.guide['revision'],
        'definition_sha256': BenchDefinition.digest,
        'snapshot': def.snapshot,
      };
    sync = BenchSync(server.call, files.benchVerified, files.markBenchVerified);
    f.sync = sync;
    s = f.session();
  });
  tearDown(() => dir.delete(recursive: true));
  Future<void> missingLabel() async {
    await f.start(s);
    await f.connected(s);
    await s.observe('No label', unavailable: true);
  }

  test('reopened prior failure and passing retry share the actual journal and portable export receipt', () async {
    await missingLabel();
    final earlier = s.report!['id'];
    await f.start(s);
    await f.connected(s);
    await s.observe('D000000000001');
    await s.export(dir.path);
    final later = s.report!['id'];
    await s.syncSelected();
    expect(server.results.keys, [earlier, later]);
    expect(server.results[earlier]!['outcome'], 'Incomplete');
    expect(server.results[later]!['outcome'], 'Passed');
    expect(server.headers[later]!['prior_attempt'], earlier);
    expect(
      server.results[later]!['export_receipt'].keys,
      unorderedEquals(['sha256', 'bytes']),
    );
    expect(jsonEncode(server.results), isNot(contains(dir.path)));
    expect(
      jsonEncode(server.results),
      isNot(contains('synthetic runner diagnostic')),
    );
    expect(jsonEncode(server.headers), isNot(contains('hardware')));
    final restarted = f.session();
    await restarted.refresh();
    await restarted.open(later);
    final requests = server.requests.length;
    await restarted.syncSelected();
    expect(
      restarted.verifiedGenerations.keys,
      unorderedEquals([earlier, later]),
    );
    expect(server.requests.length, requests);
    await files.markBenchVerified(restarted.report!);
    final markers = await dir
        .list(recursive: true)
        .where((f) => f.path.endsWith('.verified'))
        .toList();
    expect(markers, hasLength(2));
    final marker = markers.cast<File>().singleWhere(
      (f) => f.path.contains(later),
    );
    await marker.writeAsString('damaged marker');
    await expectLater(
      files.markBenchVerified(restarted.report!),
      throwsA(isA<FileSystemException>()),
    );
    await restarted.refresh();
    expect(restarted.verifiedGenerations.containsKey(later), false);
    final port = Platform.environment['OCTATRACE_BENCH_SYNTHETIC_FIXTURE'];
    if (port != null) {
      await File(port).writeAsString(
        jsonEncode({
          'headers': server.headers,
          'results': server.results,
          'objects': server.objects,
        }),
      );
    }
  });
  test('lost readback retains bytes on disk and retry skips only verified server objects', () async {
    await missingLabel();
    final report = s.report!;
    server.fault = 'offline';
    await expectLater(s.syncSelected(), throwsA(isA<SocketException>()));
    expect(await files.benchVerified(report), false);
    expect(server.objects.length, 1);
    final restarted = f.session();
    await restarted.open(report['id']);
    server.fault = null;
    await restarted.syncSelected();
    expect(
      server.requests.where((r) => r == 'workshop_put_test_artifact'),
      hasLength(1),
    );
    expect(await files.benchVerified(report), true);
    expect(
      (await files.reopenBench(fixtures.actor, report['id']))['outcome'],
      'Incomplete',
    );
  });
  test('exact definition, metadata, object and readback acknowledgements gate the receipt', () async {
    await missingLabel();
    final catalog = server.catalog;
    server.catalog = {...catalog, 'snapshot': 'wrong'};
    await expectLater(s.syncSelected(), throwsFormatException);
    expect(server.headers, isEmpty);
    server.catalog = catalog;
    for (final fault in ['run', 'count', 'manifest', 'put', 'read']) {
      server.fault = fault;
      await expectLater(s.syncSelected(), throwsFormatException, reason: fault);
      expect(await files.benchVerified(s.report!), false);
    }
  });
  test('chain and artifact validation and session interruption cannot acknowledge a different record', () async {
    await missingLabel();
    final r = s.report!;
    final id = r['id'] as String;
    final store = TestBenchStore();
    Future<void> send() => sync.upload(fixtures.actor, id, store, () => true);
    store.records[id] = {...r, 'prior_attempt': id};
    await expectLater(send(), throwsFormatException);
    store.records[id] = {...r, 'operator': fixtures.other};
    await expectLater(send(), throwsFormatException);
    store.records[id] = {
      ...r,
      'artifacts': [
        for (final a in r['artifacts']) {...a, 'content': 'altered'},
      ],
    };
    await expectLater(send(), throwsFormatException);
    bool current = true;
    final expired = BenchSync(
      (a, n, p) async {
        current = false;
        return server.call(a, n, p);
      },
      files.benchVerified,
      files.markBenchVerified,
    );
    await expectLater(
      expired.upload(fixtures.actor, id, f.store, () => current),
      throwsA(isA<SessionExpired>()),
    );
    expect(await files.benchVerified(r), false);
  });
  test('history follows ordered cursors and rejects account changes or repeated pages', () async {
    String mode = 'ok';
    bool current = true;
    final cursors = <String?>[];
    final history = BenchSync(
      (a, n, p) async {
        expect(n, 'workshop_test_runs');
        cursors.add(p['p_after']);
        if (mode == 'expired') current = false;
        return [
          for (int i = 0; i < (p['p_after'] == null ? 20 : 1); i++)
            {
              'header': {
                'id':
                    'r${(i + (p['p_after'] != null && mode != 'repeated' ? 20 : 0)).toString().padLeft(3, '0')}',
                'operator': mode == 'other' ? fixtures.other : a,
              },
            },
        ];
      },
      files.benchVerified,
      files.markBenchVerified,
    );
    expect(await history.history(fixtures.actor, () => current), hasLength(21));
    expect(cursors, [null, 'r019']);
    for (final m in ['repeated', 'other']) {
      mode = m;
      await expectLater(
        history.history(fixtures.actor, () => current),
        throwsFormatException,
      );
    }
    mode = 'expired';
    await expectLater(
      history.history(fixtures.actor, () => current),
      throwsA(isA<SessionExpired>()),
    );
  });
  test('shared attachment is bound to the operator, active session, length and binary digest', () async {
    final row = {
      'header': {'id': 'r', 'operator': fixtures.actor},
      'result': {'generation': 2},
    };
    final a = {
      'type': 'application/json',
      'bytes': 2,
      'sha256': benchHash('{}'),
    };
    bool current = true;
    var endSession = false;
    final shared = BenchSync(
      (_, n, p) async {
        expect(n, 'workshop_read_test_artifact');
        expect(p['p_run'], 'r');
        if (endSession) current = false;
        return base64Encode(utf8.encode('{}'));
      },
      files.benchVerified,
      files.markBenchVerified,
    );
    Future<String> read(String account, Json artifact) =>
        shared.readArtifact(account, row, artifact, () => current);
    expect(await read(fixtures.actor, a), '{}');
    expect(
      await read(fixtures.actor, {...a, 'type': 'application/octet-stream'}),
      contains('2 verified bytes'),
    );
    await expectLater(read(fixtures.other, a), throwsA(isA<SessionExpired>()));
    await expectLater(
      read(fixtures.actor, {...a, 'sha256': 'wrong'}),
      throwsFormatException,
    );
    endSession = true;
    await expectLater(read(fixtures.actor, a), throwsA(isA<SessionExpired>()));
  });
}
