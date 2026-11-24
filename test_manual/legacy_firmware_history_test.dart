import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/services/firmware_checks.dart';

void main() {
  test('reopens and exports an existing earlier host attempt', () async {
    final oldAttempt = Directory(
      Platform.environment['OCTATRACE_LEGACY_ATTEMPT'] ?? '',
    );
    final python = Platform.environment['OCTATRACE_FIRMWARE_TEST_PYTHON'] ?? '';
    expect(await oldAttempt.exists(), isTrue);
    expect(python, isNotEmpty);
    final started = jsonDecode(
      await File('${oldAttempt.path}/started.json').readAsString(),
    ) as Map;
    final account = started['operator'] as String;
    final id = started['id'] as String;
    final parent = Directory('build/firmware-legacy-acceptance');
    await parent.create(recursive: true);
    final temp = await parent.createTemp('run-');
    final evidence = Directory('${temp.path}/evidence');
    final copy = await Directory('${evidence.path}/$account/firmware-host/$id')
        .create(recursive: true);
    await for (final entity in oldAttempt.list(followLinks: false)) {
      if (entity is File) {
        await entity.copy(
          '${copy.path}/${entity.path.split(Platform.pathSeparator).last}',
        );
      }
    }
    final checks = ProcessFirmwareChecks(
      firmwareRoot: '',
      evidenceRoot: evidence,
      adapter: await File('tools/firmware_test_adapter.py').readAsString(),
      definition: await File('assets/bench/firmware-host-regression.v7.json')
          .readAsString(),
      newId: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      workshopFingerprint: () async => 'c' * 64,
    );
    final reports = await checks.history(account: account, python: python);
    expect(reports.single['status'], 'passed');
    expect(reports.single['attempt'], id);
    final output = await Directory('${temp.path}/exports').create();
    final path = await checks.export(
      account: account,
      python: python,
      attempt: id,
      directory: output.path,
    );
    final bundle = jsonDecode(await File(path).readAsString()) as Map;
    expect((bundle['report'] as Map)['status'], 'passed');
    expect((bundle['report'] as Map)['id'], id);
  });
}
