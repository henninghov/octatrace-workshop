import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/services/bench_runner.dart';

void main() {
  late Directory root;
  Future<void> helper(String body) async {
    final file = File('${root.path}/build/bench-venv/bin/python');
    await file.parent.create(recursive: true);
    await file.writeAsString('#!/usr/bin/env python3\n$body\n');
    final mode = await Process.run('/bin/chmod', ['700', file.path]);
    expect(mode.exitCode, 0);
  }

  Future<void> started() async {
    final marker = File('${root.path}/started');
    for (var i = 0; i < 100; i++) {
      if (await marker.exists()) return;
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    fail('Synthetic helper did not start');
  }

  setUp(() async {
    root = await Directory.systemTemp.createTemp('workshop-runner-');
    final fixture = Directory('vendor');
    for (final path in [
      'usb-bench.lock.json',
      'contracts/usb-bench/contract.json',
      'contracts/usb-bench/response.schema.json',
      'contracts/usb-bench/vectors.json',
    ]) {
      final file = File('${root.path}/$path');
      await file.parent.create(recursive: true);
      await File('${fixture.path}/$path').copy(file.path);
    }
  });
  tearDown(() async {
    await root.delete(recursive: true);
  });
  Future<Map<String, dynamic>> run(ProcessBenchRunner runner) => runner.run(
    port: '/dev/cu.usbmodemSynthetic',
    role: 'Link',
    build: 'a' * 64,
    command: 'identity',
  );
  test(
    'shared CLI receives explicit arguments and returns structured evidence',
    () async {
      await helper(
        'import json,sys\nprint(json.dumps({"args":sys.argv[1:],"ok":True}))',
      );
      final report = await run(ProcessBenchRunner(root.path));
      expect(report['ok'], true);
      expect(
        (report['args'] as List),
        containsAllInOrder([
          'identity',
          '--port',
          '/dev/cu.usbmodemSynthetic',
          '--expect-role',
          'Link',
          '--expect-build',
          'a' * 64,
        ]),
      );
    },
  );
  test(
    'contract mismatch and changed owner bytes stop before opening USB',
    () async {
      final lock = File('${root.path}/usb-bench.lock.json');
      final data = jsonDecode(await lock.readAsString()) as Map;
      data['version'] = 2;
      await lock.writeAsString(jsonEncode(data));
      await expectLater(
        run(ProcessBenchRunner(root.path)),
        throwsFormatException,
      );
      data['version'] = 1;
      data['files'] = {};
      await lock.writeAsString(jsonEncode(data));
      await expectLater(
        run(ProcessBenchRunner(root.path)),
        throwsFormatException,
      );
      await File('vendor/usb-bench.lock.json').copy(lock.path);
      await File('${root.path}/contracts/usb-bench/contract.json')
          .writeAsString('{}');
      await expectLater(
        run(ProcessBenchRunner(root.path)),
        throwsFormatException,
      );
    },
  );
  test('missing helper, invalid JSON and nonzero exit are failures', () async {
    await expectLater(
      run(ProcessBenchRunner(root.path)),
      throwsA(isA<ProcessException>()),
    );
    await helper('print("invalid JSON")');
    await expectLater(
      run(ProcessBenchRunner(root.path)),
      throwsFormatException,
    );
    await helper(
      'import sys\nprint("synthetic error",file=sys.stderr)\nsys.exit(1)',
    );
    await expectLater(run(ProcessBenchRunner(root.path)), throwsStateError);
    await helper('print("[]")');
    await expectLater(
      run(ProcessBenchRunner(root.path)),
      throwsFormatException,
    );
  });
  test('unbounded helper output is rejected', () async {
    await helper('print("x"*70000)');
    await expectLater(
      run(ProcessBenchRunner(root.path)),
      throwsFormatException,
    );
  });
  test('concurrent command rejected and Cancel closes the owned child', () async {
    await helper(
      'from pathlib import Path\nimport time\nPath(${jsonEncode('${root.path}/started')}).write_text("started")\ntime.sleep(20)',
    );
    final runner = ProcessBenchRunner(root.path);
    final first = run(runner);
    final expectation = expectLater(first, throwsA(isA<BenchCancelled>()));
    await started();
    await expectLater(run(runner), throwsStateError);
    await runner.cancel();
    await expectation;
  });
  test('Cancel kills a helper that ignores its first termination signal', () async {
    await helper(
      'from pathlib import Path\nimport signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath(${jsonEncode('${root.path}/started')}).write_text("started")\ntime.sleep(20)',
    );
    final runner = ProcessBenchRunner(root.path);
    final pending = run(runner);
    final outcome = expectLater(pending, throwsA(isA<BenchCancelled>()));
    await started();
    await runner.cancel();
    await outcome;
  });
  test('wrapper deadline stops a stuck helper', () async {
    await helper('import time\ntime.sleep(20)');
    await expectLater(
      run(
        ProcessBenchRunner(
          root.path,
          timeout: const Duration(milliseconds: 50),
        ),
      ),
      throwsA(isA<TimeoutException>()),
    );
  });
  test('Cancel during contract verification prevents a late success', () async {
    await helper('print("{}")');
    final runner = ProcessBenchRunner(root.path);
    final operation = run(runner);
    await runner.cancel();
    await expectLater(operation, throwsA(isA<BenchCancelled>()));
  });
}
