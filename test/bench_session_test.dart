import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/bench_sync.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';
import 'package:octatrace_workshop/services/bench_files.dart';

import 'provisioning_test.dart' as usb;
import 'widget_test.dart' as fixtures;

class TestBenchStore implements BenchStore {
  TestBenchStore([this.real]);
  final BenchStore? real;
  final records = <String, Json>{};
  int? failGeneration;
  bool wrongRead = false, failExport = false;
  Completer<Json>? holdReopen;
  @override
  Future<void> saveBench(Json report) async {
    if (report['generation'] == failGeneration) {
      throw const FileSystemException('disk full');
    }
    await real?.saveBench(report);
    records[report['id']] = jsonDecode(jsonEncode(report));
  }

  @override
  Future<Json> reopenBench(String account, String id) async {
    if (wrongRead) return {};
    if (holdReopen != null) return holdReopen!.future;
    return real != null ? await real!.reopenBench(account, id) : records[id]!;
  }

  @override
  Future<List<Json>> benchHistory(String account) async => real != null
      ? await real!.benchHistory(account)
      : records.values.toList().reversed.toList();
  @override
  Future<({String path, String digest, int bytes})> exportBench(
    Json report,
    String folder,
  ) async {
    if (failExport) throw const FileSystemException('export interrupted');
    return real != null
        ? await real!.exportBench(report, folder)
        : (path: 'test/export.json', digest: 'a' * 64, bytes: 123);
  }
}

class BenchFixture {
  BenchFixture(this.store, this.definition);
  final TestBenchStore store;
  final BenchDefinition definition;
  final gateway = usb.SetupGateway()..completed = true;
  final usbRunner = usb.SetupRunner();
  late Registry registry;
  BenchSync? sync;
  int ids = 0, reads = 0;
  String fingerprint = 'a' * 64;
  Completer<Json>? inventory, response;
  Object? error;
  bool seenRead = false, seenDiscovery = false;
  Future<void> init() async {
    registry = await gateway.load();
  }

  BenchSession session([String account = fixtures.actor]) => BenchSession(
    account,
    definition,
    store,
    (a, d) async {
      seenDiscovery = true;
      return inventory != null
          ? await inventory!.future
          : await usbRunner.execute(account: a, command: 'inventory');
    },
    usbRunner.cancel,
    (a, r, {onDiagnostic}) async {
      reads++;
      seenRead = true;
      onDiagnostic?.call({'bounded': 'synthetic runner diagnostic'});
      if (error != null) throw error!;
      return response != null
          ? await response!.future
          : {
              'device_id': r.device.id,
              'serial': r.device.serial,
              'role': r.build.role,
              'build': r.build.source,
            };
    },
    () async => fingerprint,
    () => '90510000-0000-4000-8000-${(++ids).toString().padLeft(12, '0')}',
    () => DateTime.utc(2026, 11, 20, 12, 0, ids),
    sync: sync,
  );
  Future<void> start(BenchSession s) =>
      s.start(registry.devices.single, registry.articles.single);
  Future<void> connected(BenchSession s) =>
      s.connected(registry.devices.single, registry.articles.single);
}

void main() {
  final def = BenchDefinition.fromSnapshot(
    File(BenchDefinition.asset).readAsStringSync(),
  );
  late Directory root, out;
  late EvidenceJournal files;
  late BenchFixture f;
  late BenchSession s;
  setUp(() async {
    root = await Directory.systemTemp.createTemp('octatrace-bench-session-');
    out = await Directory('${root.path}/out').create();
    files = EvidenceJournal(Directory('${root.path}/evidence'));
    f = BenchFixture(TestBenchStore(files), def);
    await f.init();
    s = f.session();
  });
  tearDown(() async => root.delete(recursive: true));
  test('real files survive process recreation and export has distinct tester and runner evidence', () async {
    await s.perform(() => f.start(s));
    final id = s.report!['id'];
    final restarted = f.session();
    await restarted.refresh();
    await restarted.open(id);
    expect(restarted.active, isFalse);
    expect(restarted.report!['outcome'], 'Incomplete');
    expect(restarted.next, 3);
    expect(f.seenDiscovery, isFalse);
    expect(await files.benchHistory(fixtures.other), isEmpty);
    await expectLater(s.open(id), throwsStateError);
    await expectLater(f.start(s), throwsStateError);
    await expectLater(s.export(out.path), throwsStateError);
    await f.connected(s);
    expect(s.next, 5);
    await expectLater(f.connected(s), throwsStateError);
    await expectLater(s.observe('  '), throwsFormatException);
    await s.observe(' D000000000001 ');
    expect(s.next, 7);
    expect(s.report!['steps'][4]['evidence']['observation'], 'D000000000001');
    expect(s.report!['steps'][4]['evaluation'], 'observation');
    expect(s.report!['steps'][3]['evaluation'], 'automatic');
    final path = await s.export(out.path);
    final bytes = await File(path).readAsString();
    final exported = readBenchEnvelope(bytes, fixtures.actor, id);
    expect(exported['outcome'], 'Passed');
    expect(exported['definition_snapshot'], def.snapshot);
    expect(
      exported['artifacts'].single['content'],
      contains('synthetic runner diagnostic'),
    );
    expect(exported['steps'].map((x) => x['status']), everyElement('Passed'));
    await restarted.open(id);
    expect(restarted.report!['exports'].single['sha256'], benchHash(bytes));
    expect(
      restarted.report!['exports'].single['bytes'],
      utf8.encode(bytes).length,
    );
    expect(await files.pending(fixtures.actor), isEmpty);
    final review = await restarted.export(out.path);
    expect(await restarted.export(out.path), review);
    expect(review, isNot(path));
    await f.start(restarted);
    expect(restarted.report!['prior_attempt'], id);
    expect(restarted.report!['id'], isNot(id));
    expect((await files.reopenBench(fixtures.actor, id))['outcome'], 'Passed');
  });

  test('blocked target, wrong binding, process error, missing and wrong label retain the failed step', () async {
    Future<void> read() async {
      await f.start(s);
      await f.connected(s);
    }

    f.usbRunner.absent = true;
    await read();
    expect(s.report!['outcome'], 'Blocked');
    f.usbRunner.absent = false;
    f.error = const ProvisioningFailure('Malformed response');
    await read();
    expect(s.report!['steps'][3]['evidence']['error'], 'Malformed response');
    f.error = const BenchBlocked('wrong build');
    await read();
    expect(s.report!['outcome'], 'Blocked');
    f.error = TimeoutException('USB timed out');
    await read();
    expect(s.report!['outcome'], 'Failed');
    f.error = null;
    await read();
    await s.observe('unreadable', unavailable: true);
    expect(s.report!['outcome'], 'Incomplete');
    await read();
    await s.observe('D000000000124');
    expect(s.report!['outcome'], 'Failed');
    expect(s.report!['steps'][5]['status'], 'Not run');
    await read();
    await s.observe('D000000000001');
    f.store.failExport = true;
    await expectLater(s.export(out.path), throwsA(isA<FileSystemException>()));
    expect(s.report!['outcome'], 'Incomplete');
    expect(
      s.report!['steps'][6]['evidence']['export_error'],
      contains('export interrupted'),
    );
    expect((await files.benchHistory(fixtures.actor)), hasLength(7));
  });

  test('local save failures retain pending data, no hardware before start, no duplicate read on retry', () async {
    f.fingerprint = 'bad';
    await expectLater(f.start(s), throwsFormatException);
    f.fingerprint = 'a' * 64;
    f.store.failGeneration = 1;
    await expectLater(f.start(s), throwsA(isA<FileSystemException>()));
    expect(f.seenDiscovery, isFalse);
    expect(s.pending!['id'], isNotEmpty);
    expect(s.report, isNull);
    f.store.failGeneration = null;
    await s.retrySave();
    expect(s.next, 3);
    f.store.failGeneration = 2;
    await expectLater(f.connected(s), throwsA(isA<FileSystemException>()));
    expect(f.seenDiscovery, isFalse);
    f.store.failGeneration = null;
    await s.retrySave();
    expect(s.next, 4);
    f.store.failGeneration = 3;
    await expectLater(
      s.readDevice(f.registry.devices.single, f.registry.articles.single),
      throwsA(isA<FileSystemException>()),
    );
    expect(s.pending!['artifacts'], hasLength(1));
    f.store.failGeneration = null;
    await s.retrySave();
    expect(f.reads, 1);
    f.store.wrongRead = true;
    await expectLater(s.observe('D000000000001'), throwsFormatException);
    await expectLater(s.export(out.path), throwsStateError);
    f.store.wrongRead = false;
    await s.verifyReopen();
    expect(s.next, 7);
    await expectLater(
      s.export('relative'),
      throwsA(isA<FileSystemException>()),
    );
    expect(s.report!['outcome'], 'Incomplete');
  });

  test('cancel and logout during discovery or read discard late completion and retain original account', () async {
    for (final discovery in [true, false]) {
      s = f.session();
      await f.start(s);
      f.inventory = discovery ? Completer<Json>() : null;
      f.response = Completer<Json>();
      f.seenDiscovery = false;
      f.seenRead = false;
      final running = s.perform(() => f.connected(s));
      while (discovery ? !f.seenDiscovery : !f.seenRead) {
        await Future<void>.delayed(const Duration(milliseconds: 1));
      }
      expect(() => s.perform(() async {}), throwsStateError);
      final cancellation = s.stop(
        discovery ? 'Operator cancelled' : 'Operator session ended',
      );
      if (discovery) {
        f.inventory!.complete({});
      } else {
        f.response!.complete({'late': true});
      }
      await running;
      await cancellation;
      expect(s.report!['outcome'], discovery ? 'Cancelled' : 'Interrupted');
      expect(s.report!['steps'][3]['status'], 'Incomplete');
      expect(jsonEncode(s.report), isNot(contains('late')));
      expect(s.report!['steps'][4]['status'], 'Not run');
    }
    expect(await files.benchHistory(fixtures.other), isEmpty);
  });

  test('immutable generations, checksums, artifact lengths and private exports reject conflicting bytes', () async {
    await f.start(s);
    final first = s.report!, id = first['id'];
    await files.saveBench(first);
    await expectLater(
      files.saveBench({...first, 'outcome': 'Passed'}),
      throwsA(isA<FileSystemException>()),
    );
    await expectLater(
      files.saveBench({...first, 'generation': 3}),
      throwsFormatException,
    );
    await expectLater(
      files.reopenBench(fixtures.actor, '../other'),
      throwsFormatException,
    );
    await f.connected(s);
    final r = s.report!;
    final envelope = benchEnvelope(r);
    expect(
      () => readBenchEnvelope(envelope, fixtures.other, id),
      throwsFormatException,
    );
    expect(
      () => readBenchEnvelope(
        envelope.replaceFirst('Incomplete', 'Passed'),
        fixtures.actor,
        id,
      ),
      throwsFormatException,
    );
    final tampered = jsonDecode(jsonEncode(r)) as Json;
    tampered['artifacts'][0]['bytes']++;
    expect(
      () => readBenchEnvelope(benchEnvelope(tampered), fixtures.actor, id),
      throwsFormatException,
    );
    final destination = await files.exportBench(r, out.path);
    await File(destination.path).writeAsString('truncated');
    await expectLater(files.exportBench(r, out.path), throwsFormatException);
    final dir = Directory('${files.root.path}/${fixtures.actor}/bench/$id');
    final bad = File('${dir.path}/4.json');
    await bad.writeAsString(envelope);
    await expectLater(
      files.reopenBench(fixtures.actor, id),
      throwsFormatException,
    );
    await bad.rename('${dir.path}/5.json');
    await expectLater(
      files.reopenBench(fixtures.actor, id),
      throwsFormatException,
    );
  });
  test('Workshop fingerprint covers both native and Flutter bundle bytes and relative names', () async {
    await expectLater(
      workshopBundleFingerprint(out),
      throwsA(isA<FileSystemException>()),
    );
    final a = File('${out.path}/Workshop');
    await a.writeAsString('MachO');
    final b = File('${out.path}/kernel');
    await b.writeAsString('Flutter');
    final hash = await workshopBundleFingerprint(out);
    await b.writeAsString('changed');
    expect(await workshopBundleFingerprint(out), isNot(hash));
    await b.writeAsString('Flutter');
    await b.rename('${out.path}/other');
    expect(await workshopBundleFingerprint(out), isNot(hash));
    await expectLater(
      workshopBundleFingerprint(),
      throwsA(isA<FileSystemException>()),
    );
  });
  test(
    'verified label survives quit and the final export completes after restart',
    () async {
      await f.start(s);
      await f.connected(s);
      await s.observe('D000000000001');
      final id = s.report!['id'];
      await s.stop('Operator session ended');
      expect(s.active, isFalse);
      final restarted = f.session();
      await restarted.open(id);
      expect(restarted.report!['outcome'], 'Awaiting export');
      final path = await restarted.export(out.path);
      expect(restarted.report!['outcome'], 'Passed');
      expect((await File(path).stat()).mode & 511, 384);
      expect(f.reads, 1);
    },
  );

  test('logout before export publication and ambiguous discovery retain explicit outcomes', () async {
    f.inventory = Completer<Json>()
      ..complete({
        'targets': [usb.targetJson(), usb.targetJson()],
        'builds': [],
      });
    await f.start(s);
    await f.connected(s);
    expect(s.report!['outcome'], 'Blocked');
    f.inventory = null;
    await f.start(s);
    await f.connected(s);
    await s.observe('D000000000001');
    f.store.holdReopen = Completer<Json>();
    final exporting = s.perform(() async {
      await s.export(out.path);
    });
    final rejected = expectLater(exporting, throwsStateError);
    final stop = s.stop('Operator session ended');
    f.store.holdReopen!.complete(s.report);
    await rejected;
    await stop;
    expect(await out.list().isEmpty, isTrue);
    expect(s.report!['outcome'], 'Awaiting export');
  });

  test(
    'recomputed outer checksum cannot admit changed build or definition',
    () async {
      await f.start(s);
      final altered = jsonDecode(jsonEncode(s.report)) as Json;
      altered['firmware']['source'] = 'e' * 64;
      expect(
        () =>
            readBenchEnvelope(benchEnvelope(altered), s.account, altered['id']),
        throwsFormatException,
      );
      altered['definition_snapshot'] = '{}';
      altered['definition_sha256'] = benchHash('{}');
      expect(
        () =>
            readBenchEnvelope(benchEnvelope(altered), s.account, altered['id']),
        throwsFormatException,
      );
    },
  );
}
