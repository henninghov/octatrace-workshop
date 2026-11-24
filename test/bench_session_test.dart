import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';
import 'package:octatrace_workshop/services/bench_files.dart';

import 'provisioning_test.dart' as usb;
import 'widget_test.dart' as fixtures;
import 'support/bench_fixture.dart';

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
  test('revision 1 credential attempts reopen and export without changing their guide', () async {
    for (final name in [
      'credential-readiness',
      'credential-installation',
      'credential-intent-stop',
      'credential-preparation',
    ]) {
      final legacy = BenchDefinition.fromSnapshot(
        File('assets/bench/$name.v1.json').readAsStringSync(),
      );
      final separate = BenchFixture(
        TestBenchStore(EvidenceJournal(Directory('${root.path}/$name'))),
        legacy,
      );
      await separate.init();
      final session = separate.session();
      await separate.start(session);
      await session.stop('Operator cancelled');
      final id = session.report!['id'] as String;
      final before = jsonEncode(session.report);
      await session.open(id);
      await session.export(out.path);
      expect(jsonEncode(session.report), before);
      expect(session.report!['definition_snapshot'], legacy.snapshot);
      expect(session.report!['definition_sha256'], legacy.snapshotDigest);
      expect(session.report!['outcome'], 'Cancelled');
    }
  });
  tearDown(() async => root.delete(recursive: true));
  test(
    'legacy attempts retain the original definition digest on disk',
    () async {
      final legacy = BenchDefinition.fromSnapshot(
        File(BenchDefinition.legacyAsset).readAsStringSync(),
      );
      final fixture = BenchFixture(TestBenchStore(files), legacy);
      await fixture.init();
      final session = fixture.session();
      await fixture.start(session);
      final report = session.report!;
      expect(report['definition_revision'], 1);
      expect(report['definition_sha256'], BenchDefinition.legacyDigest);
      final reopened = await files.reopenBench(fixtures.actor, report['id']);
      expect(
        readBenchEnvelope(
          benchEnvelope(reopened),
          fixtures.actor,
          report['id'],
        )['definition_sha256'],
        BenchDefinition.legacyDigest,
      );
    },
  );

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

  test('delivery saves separate verified observation and never saves credential bytes', () async {
    f.delivery = BenchDefinition.fromSnapshot(
      File(BenchDefinition.deliveryAsset).readAsStringSync(),
    );
    s = f.session();
    s.selectDefinition(f.delivery!);
    await f.start(s);
    await f.connected(s);
    expect(f.credentials, 1);
    expect(f.deliveryReads, 1);
    expect(s.report!['steps'][3]['evidence']['frame']['state'], 'verified');
    await s.observe('verified');
    expect(s.next, 7);
    await s.export(out.path);
    expect(s.report!['outcome'], 'Passed');
    expect(jsonEncode(s.report), isNot(contains('010203')));
    expect(s.report!['steps'][4]['evidence']['observation'], 'verified');
  });

  test('logout while fetching a credential prevents the USB delivery', () async {
    f.delivery = BenchDefinition.fromSnapshot(
      File(BenchDefinition.deliveryAsset).readAsStringSync(),
    );
    f.heldCredential = Completer<PublicFactoryCredential>();
    s = f.session();
    s.selectDefinition(f.delivery!);
    await f.start(s);
    final running = s.perform(() => f.connected(s));
    while (f.credentials == 0) {
      await Future<void>.delayed(const Duration(milliseconds: 1));
    }
    final stopped = s.stop('Operator session ended');
    final device = f.registry.devices.single,
        article = f.registry.articles.single;
    f.heldCredential!.complete(
      PublicFactoryCredential.fromJson(
        {
          'v': 1,
          'device_id': device.id,
          'role': article.role,
          'credential': '010203',
          'credential_sha256': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
        },
        deviceId: device.id,
        role: article.role,
        expectedDigest:
            '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
      ),
    );
    await running;
    await stopped;
    expect(f.deliveryReads, 0);
    expect(s.report!['outcome'], 'Interrupted');
    expect(jsonEncode(s.report), isNot(contains('010203')));
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
