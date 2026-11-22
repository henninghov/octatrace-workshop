import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
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
}
