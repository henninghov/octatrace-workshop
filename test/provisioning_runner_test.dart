import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/provisioning_runner.dart';

import 'widget_test.dart' as f;
import 'provisioning_test.dart' as p;

void main() {
  late Directory root;
  ProcessProvisioningRunner runner({
    Duration timeout = const Duration(seconds: 10),
    Future<Process> Function(String, List<String>)? start,
  }) => ProcessProvisioningRunner(
    root.path,
    Directory('${root.path}/evidence'),
    timeout: timeout,
    startProcess: start,
  );
  Future<void> helper(String body) async {
    final file = File('${root.path}/build/bench-venv/bin/python');
    await file.parent.create(recursive: true);
    await file.writeAsString('#!/usr/bin/env python3\n$body\n');
    expect((await Process.run('/bin/chmod', ['700', file.path])).exitCode, 0);
  }

  Future<void> started() async {
    final marker = File('${root.path}/started');
    for (var i = 0; i < 200; i++) {
      if (await marker.exists()) return;
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    fail('Helper did not start');
  }

  Future<Json> execute(
    ProcessProvisioningRunner r, {
    String command = 'inventory',
    Json parameters = const {},
  }) => r.execute(account: f.actor, command: command, parameters: parameters);
  setUp(() async {
    root = await Directory.systemTemp.createTemp('workshop-usb-adapter-');
    for (final path in [
      'usb-provisioning.lock.json',
      ...ProcessProvisioningRunner.pins.keys,
    ]) {
      final target = File('${root.path}/$path');
      await target.parent.create(recursive: true);
      await File('vendor/$path').copy(target.path);
    }
  });
  tearDown(() async {
    await root.delete(recursive: true);
  });
  test(
    'structured args and public-only stdin preserve private account partition',
    () async {
      await helper(
        'import json,sys\nprint(json.dumps({"args":sys.argv[1:],"input":json.load(sys.stdin) if "provision" in sys.argv else None}))',
      );
      final r = runner();
      final inventory = await execute(r);
      expect(inventory['input'], isNull);
      final identity = await execute(
        r,
        command: 'identity',
        parameters: {'hardware': p.hardware, 'source': 'a' * 64},
      );
      expect(
        identity['args'],
        containsAllInOrder([
          'identity',
          '--hardware',
          p.hardware,
          '--source',
          'a' * 64,
        ]),
      );
      final install = await execute(
        r,
        command: 'install',
        parameters: {
          'hardware': p.hardware,
          'manifest': '/selected/manifest.json',
          'volume': '/Volumes/SYNTHETIC',
        },
      );
      expect(
        install['args'],
        containsAllInOrder([
          '--manifest',
          '/selected/manifest.json',
          '--volume',
          '/Volumes/SYNTHETIC',
          '--evidence-root',
          '${root.path}/evidence/${f.actor}/usb',
        ]),
      );
      final report = await execute(
        r,
        command: 'provision',
        parameters: {
          'device_id': f.device,
          'access_token': 'must-not-reach-child',
        },
      );
      expect((report['input'] as Map).containsKey('access_token'), isFalse);
      expect((report['input'] as Map)['device_id'], f.device);
      final logs = await Directory(
        '${root.path}/evidence/${f.actor}/usb/adapter',
      ).list().toList();
      expect(logs.length, 3);
      expect(
        (await logs.last.stat()).mode & 0x1ff,
        0x1c0,
      ); // 0700 private directory
      final retained = jsonDecode(
        await File('${logs.last.path}/result.json').readAsString(),
      );
      expect(retained['exit_code'], 0);
    },
  );
  test('invalid account, command, hardware, source and oversized input stop before spawn', () async {
    final r = runner();
    await expectLater(
      r.execute(account: '../escape', command: 'inventory'),
      throwsFormatException,
    );
    await expectLater(execute(r, command: 'delete'), throwsFormatException);
    await expectLater(
      execute(r, command: 'identity', parameters: {'hardware': 'bad'}),
      throwsFormatException,
    );
    await expectLater(
      execute(
        r,
        command: 'identity',
        parameters: {'hardware': p.hardware, 'source': 'bad'},
      ),
      throwsFormatException,
    );
    await expectLater(
      execute(r, command: 'provision', parameters: {'public_key': 'x' * 9000}),
      throwsFormatException,
    );
  });
  test(
    'pins reject unknown version, changed inventory and changed owner bytes',
    () async {
      final file = File('${root.path}/usb-provisioning.lock.json'),
          original = await File('vendor/usb-provisioning.lock.json')
              .readAsString();
      final bad = jsonDecode(original) as Json;
      bad['version'] = 2;
      await file.writeAsString(jsonEncode(bad));
      await expectLater(execute(runner()), throwsFormatException);
      bad['version'] = 1;
      bad['files'] = {};
      await file.writeAsString(jsonEncode(bad));
      await expectLater(execute(runner()), throwsFormatException);
      await file.writeAsString(original);
      await File('${root.path}/contracts/usb-provisioning/contract.json')
          .writeAsString('{}');
      await expectLater(execute(runner()), throwsFormatException);
    },
  );
  test('nonzero child result retains diagnostic privately and rejects confirmation', () async {
    await helper(
      'import sys\nprint("synthetic USB failure",file=sys.stderr)\nsys.exit(1)',
    );
    await expectLater(
      execute(runner(), command: 'provision'),
      throwsA(isA<ProvisioningFailure>()),
    );
    final logs = await Directory('${root.path}/evidence/${f.actor}/usb/adapter')
        .list()
        .toList();
    final saved = jsonDecode(
      await File('${logs.single.path}/result.json').readAsString(),
    );
    expect(
      utf8.decode(base64Decode(saved['stderr_base64'])),
      contains('synthetic USB failure'),
    );
  });
  test(
    'malformed JSON, missing binary and excessive stdout fail closed',
    () async {
      await expectLater(execute(runner()), throwsA(isA<ProcessException>()));
      for (final body in [
        'print("invalid")',
        'print("[]")',
        'print("x"*70000)',
      ]) {
        await helper(body);
        await expectLater(execute(runner()), throwsFormatException);
      }
    },
  );
  test('busy guard, cancellation and timeout stop the owned child', () async {
    await helper(
      'from pathlib import Path\nimport time\nPath(${jsonEncode('${root.path}/started')}).write_text("started")\ntime.sleep(20)',
    );
    final r = runner();
    final future = execute(r);
    final result = expectLater(future, throwsA(isA<BenchCancelled>()));
    await started();
    await expectLater(execute(r), throwsStateError);
    await r.cancel();
    await result;
    await expectLater(
      execute(runner(timeout: const Duration(milliseconds: 50))),
      throwsA(isA<TimeoutException>()),
    );
  });
  test('cancellation during pin verification starts no late child', () async {
    await helper('print("{}")');
    final r = runner();
    final future = execute(r);
    await r.cancel();
    await expectLater(future, throwsA(isA<BenchCancelled>()));
  });
  test(
    'cancel at process-start boundary kills the real child before success',
    () async {
      await helper('import time\ntime.sleep(20)');
      final created = Completer<Process>();
      final release = Completer<Process>();
      final r = runner(
        start: (path, args) async {
          final child = await Process.start(path, args);
          created.complete(child);
          return release.future;
        },
      );
      final future = execute(r);
      final result = expectLater(future, throwsA(isA<BenchCancelled>()));
      final child = await created.future;
      await r.cancel();
      release.complete(child);
      await result;
    },
  );
  test('Cancel escalates when child ignores SIGTERM', () async {
    await helper(
      'from pathlib import Path\nimport signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath(${jsonEncode('${root.path}/started')}).write_text("started")\ntime.sleep(20)',
    );
    final r = runner();
    final future = execute(r);
    final result = expectLater(future, throwsA(isA<BenchCancelled>()));
    await started();
    await r.cancel();
    await result;
  });
  test(
    'preparation commands pass public binding and require current confirmation',
    () async {
      await helper(
        'import json,sys\nprint(json.dumps({"args":sys.argv[1:],"input":json.load(sys.stdin)}))',
      );
      for (final command in ['inspect-storage', 'prepare-storage']) {
        final report = await execute(
          runner(),
          command: command,
          parameters: {
            ...p.SetupGateway().attempt(),
            'manifest': '/synthetic/manifest.json',
            'inspection_token': 'd' * 64,
            'access_token': 'must-not-reach-child',
          },
        );
        expect(
          report['args'],
          containsAllInOrder([
            '--manifest',
            '/synthetic/manifest.json',
            '--evidence-root',
          ]),
        );
        expect((report['input'] as Map).containsKey('access_token'), isFalse);
        expect(
          (report['input'] as Map).containsKey('inspection_token'),
          command == 'prepare-storage',
        );
      }
      await expectLater(
        execute(
          runner(),
          command: 'prepare-storage',
          parameters: {
            ...p.SetupGateway().attempt(),
            'manifest': '/synthetic/manifest.json',
            'inspection_token': 'bad',
          },
        ),
        throwsFormatException,
      );
      await helper('raise SystemExit(1)');
      await expectLater(
        execute(
          runner(),
          command: 'inspect-storage',
          parameters: {
            ...p.SetupGateway().attempt(),
            'manifest': '/synthetic/manifest.json',
          },
        ),
        throwsA(isA<ProvisioningFailure>()),
      );
    },
  );
  test('CORE product role is passed explicitly without credentials', () async {
    await helper(
      'import json,sys\nprint(json.dumps({"args":sys.argv[1:],"input":json.load(sys.stdin) if "provision" in sys.argv else None}))',
    );
    final r = runner();
    final identity = await execute(
      r,
      command: 'identity',
      parameters: {'hardware': p.hardware, 'source': 'a' * 64, 'role': 'Core'},
    );
    expect(identity['args'], containsAllInOrder(['--role', 'Core']));
    final result = await execute(
      r,
      command: 'provision',
      parameters: {
        ...p.SetupGateway().attempt(),
        'role': 'Core',
        'access_token': 'must-not-reach-child',
      },
    );
    final input = result['input'] as Map;
    expect(input['role'], 'Core');
    expect(input.containsKey('access_token'), isFalse);
    await expectLater(
      execute(
        r,
        command: 'identity',
        parameters: {
          'hardware': p.hardware,
          'source': 'a' * 64,
          'role': 'Terminal',
        },
      ),
      throwsFormatException,
    );
  });
}
