import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/firmware_checks.dart';
import 'package:octatrace_workshop/ui/firmware_checks_panel.dart';

import 'support/firmware_checks_fixture.dart';

void main() {
  Future<void> open(WidgetTester tester, FakeFirmwareChecks fake) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: FirmwareChecksPanel(
              checks: fake,
              account: 'operator-a',
              initialFirmware: '/firmware',
              initialPython: '/python',
              initialFonts: '/fonts',
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Firmware host regression tests'));
    await tester.pumpAndSettle();
  }

  testWidgets('run, cancel, reopen and export show the selected report', (
    tester,
  ) async {
    final fake = FakeFirmwareChecks();
    await open(tester, fake);
    expect(find.textContaining('does not establish a device'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('firmware-test-suite')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Firmware native host regression').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Run firmware tests'));
    await tester.pump();
    expect(fake.selectedSuite, FirmwareHostSuite.host);
    expect(fake.account, 'operator-a');
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pump();
    expect(fake.cancels, 1);
    fake.pending!.complete(fake.reports.first);
    await tester.pumpAndSettle();
    expect(find.text('Status: passed'), findsOneWidget);
    expect(find.text('Operator: operator-a'), findsOneWidget);
    expect(find.text('Firmware source: source-a'), findsOneWidget);
    expect(find.text('Workshop build: workshop-a'), findsOneWidget);
    await tester.ensureVisible(find.text('Reopen reports'));
    await tester.tap(find.text('Reopen reports'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(
      find.byKey(const ValueKey('firmware-test-history')),
    );
    await tester.tap(find.byKey(const ValueKey('firmware-test-history')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('host · failed · attempt-b').last);
    await tester.pumpAndSettle();
    expect(find.text('Reason: synthetic failure'), findsOneWidget);
    final folder = find.byKey(const ValueKey('firmware-test-export-folder'));
    await tester.ensureVisible(folder);
    await tester.enterText(folder, '/exports');
    await tester.ensureVisible(find.text('Export selected report'));
    await tester.tap(find.text('Export selected report'));
    await tester.pumpAndSettle();
    expect(fake.selectedAttempt, 'attempt-b');
    expect(fake.exportFolder, '/exports');
    expect(find.text('Exported report: /exports/report.json'), findsOneWidget);
    fake.fail = true;
    await tester.tap(find.text('Export selected report'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Report could not be exported'), findsOneWidget);
  });

  testWidgets('errors remain visible and do not produce a pass', (
    tester,
  ) async {
    final fake = FakeFirmwareChecks()..fail = true;
    await open(tester, fake);
    await tester.tap(find.text('Run firmware tests'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Test could not complete'), findsOneWidget);
    expect(find.text('Status: passed'), findsNothing);
    await tester.tap(find.text('Reopen reports'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Reports could not be opened'), findsOneWidget);
  });

  testWidgets('resource entries remain reachable in a short viewport', (
    tester,
  ) async {
    final fake = FakeFirmwareChecks();
    await open(tester, fake);
    await tester.tap(find.byKey(const ValueKey('firmware-test-suite')));
    await tester.pumpAndSettle();
    await tester.drag(find.byType(Scrollable).last, const Offset(0, -600));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Authority resources qualification').last);
    await tester.pumpAndSettle();
    expect(
      find.textContaining('Requires a current LINK build'),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const ValueKey('firmware-test-suite')));
    await tester.pumpAndSettle();
    await tester.drag(find.byType(Scrollable).last, const Offset(0, -600));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Authority layout qualification').last);
    await tester.pumpAndSettle();
    expect(find.textContaining('makes a separate LINK build'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('firmware-test-suite')));
    await tester.pumpAndSettle();
    await tester.drag(find.byType(Scrollable).last, const Offset(0, -600));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Field resources qualification').last);
    await tester.pumpAndSettle();
    expect(
      find.textContaining('first repeats the native host tests'),
      findsOneWidget,
    );
    await tester.ensureVisible(find.text('Run firmware tests'));
    await tester.tap(find.text('Run firmware tests'));
    await tester.pump();
    expect(fake.selectedSuite, FirmwareHostSuite.fieldResources);
    fake.pending!.complete(fake.reports.first);
    await tester.pumpAndSettle();
  });
}
