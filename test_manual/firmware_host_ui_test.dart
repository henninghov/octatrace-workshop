import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/services/firmware_checks.dart';
import 'package:octatrace_workshop/ui/firmware_checks_panel.dart';

void main() {
  late String firmware, python, suite, fonts;
  late Directory attemptRoot, exports;
  late ProcessFirmwareChecks checks;
  setUpAll(() async {
    firmware = Platform.environment['OCTATRACE_FIRMWARE_ROOT'] ?? '';
    python = Platform.environment['OCTATRACE_FIRMWARE_TEST_PYTHON'] ?? '';
    suite = Platform.environment['OCTATRACE_FIRMWARE_SUITE'] ?? 'tooling';
    fonts = Platform.environment['OCTATRACE_FIRMWARE_FONTS'] ?? '';
    expect(firmware, isNotEmpty, reason: 'Set OCTATRACE_FIRMWARE_ROOT');
    expect(python, isNotEmpty, reason: 'Set OCTATRACE_FIRMWARE_TEST_PYTHON');
    expect({
      'tooling',
      'host',
      'authorityStorage',
      'claimQr',
      'deviceAuthority',
      'deviceCredential',
      'fieldHandshake',
      'proofContext',
      'setupTransfer',
      'sessionControl',
      'authorityResources',
      'fieldResources',
      'authorityLayout',
    }, contains(suite));
    if (suite == 'host') {
      expect(fonts, isNotEmpty, reason: 'Set OCTATRACE_FIRMWARE_FONTS');
    }
    final parent = Directory('build/firmware-ui-acceptance');
    await parent.create(recursive: true);
    attemptRoot = await parent.createTemp('run-');
    exports = await Directory('${attemptRoot.path}/exports').create();
    checks = ProcessFirmwareChecks(
      firmwareRoot: firmware,
      evidenceRoot: Directory('${attemptRoot.path}/evidence'),
      adapter: await File('tools/firmware_test_adapter.py').readAsString(),
      definition: await File('assets/bench/firmware-host-regression.v7.json')
          .readAsString(),
      newId: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      workshopFingerprint: () async => 'c' * 64,
    );
  });
  testWidgets('operator runs, reopens and exports a real firmware host suite', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(1200, 1600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: FirmwareChecksPanel(
              checks: checks,
              account: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              initialFirmware: firmware,
              initialPython: python,
              initialFonts: fonts,
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Firmware host regression tests'));
    await tester.pumpAndSettle();
    if (suite != 'tooling') {
      const titles = {
        'host': 'Firmware native host regression',
        'authorityStorage': 'Authority storage qualification',
        'claimQr': 'Claim QR qualification',
        'deviceAuthority': 'Device authority qualification',
        'deviceCredential': 'Device credential qualification',
        'fieldHandshake': 'Field handshake metadata qualification',
        'proofContext': 'Proof context qualification',
        'setupTransfer': 'Setup transfer qualification',
        'sessionControl': 'Session control qualification',
        'authorityResources': 'Authority resources qualification',
        'fieldResources': 'Field resources qualification',
        'authorityLayout': 'Authority layout qualification',
      };
      await tester.tap(find.byKey(const ValueKey('firmware-test-suite')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text(titles[suite]!).last);
      await tester.tap(find.text(titles[suite]!).last);
      await tester.pumpAndSettle();
    }
    await tester.runAsync(() => tester.tap(find.text('Run firmware tests')));
    await tester.pump();
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    for (
      var i = 0;
      i <
              (suite == 'fieldResources' || suite == 'authorityLayout'
                  ? 600
                  : 240) &&
          find.text('Status: passed').evaluate().isEmpty;
      i++
    ) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(seconds: 1)),
      );
      await tester.pump();
      if (find.text('Status: failed').evaluate().isNotEmpty ||
          find
              .textContaining('Test could not complete')
              .evaluate()
              .isNotEmpty) {
        break;
      }
    }
    expect(find.text('Status: passed'), findsOneWidget);
    await tester.ensureVisible(find.text('Reopen reports'));
    await tester.runAsync(() => tester.tap(find.text('Reopen reports')));
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(seconds: 1)),
    );
    await tester.pump();
    expect(find.text('Status: passed'), findsOneWidget);
    final field = find.byKey(const ValueKey('firmware-test-export-folder'));
    await tester.ensureVisible(field);
    await tester.enterText(field, exports.absolute.path);
    await tester.ensureVisible(find.text('Export selected report'));
    await tester.runAsync(
      () => tester.tap(find.text('Export selected report')),
    );
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(seconds: 1)),
    );
    await tester.pump();
    final bundle = await tester.runAsync(() async {
      final files = await exports
          .list()
          .where((e) => e is File)
          .cast<File>()
          .toList();
      expect(files, hasLength(1));
      return jsonDecode(await files.single.readAsString()) as Map;
    });
    expect(bundle, isNotNull);
    final report = bundle!['report'] as Map;
    expect(report['status'], 'passed');
    expect(report['suite'], suite);
    expect(report['operator'], 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
    expect(report['id'], 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    expect(report['workshop_fingerprint'], 'c' * 64);
    expect(report['discovered_python_cases'], greaterThanOrEqualTo(371));
    expect(report['firmware_source_id'], matches(RegExp(r'^[0-9a-f]{64}$')));
    expect(
      (bundle['evidence'] as Map)['output.log'],
      contains(
        suite == 'host' || suite == 'sessionControl'
            ? 'PASS '
            : suite == 'tooling'
            ? 'Ran '
            : '"result": "pass"',
      ),
    );
    // The acceptance attempt and export are retained under build for review.
  }, timeout: const Timeout(Duration(minutes: 12)));
}
