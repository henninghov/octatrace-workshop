import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/bench_sync.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'bench_session_test.dart' show BenchFixture, TestBenchStore;
import 'ui_flow_test.dart' show MemoryEvidence;
import 'widget_test.dart' as fixtures;

void main() {
  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final font = FontLoader('Excon')
      ..addFont(rootBundle.load('assets/fonts/Excon-Regular.otf'))
      ..addFont(rootBundle.load('assets/fonts/Excon-Medium.otf'));
    await font.load();
    await const SvgAssetLoader('assets/branding/wordmark.svg').loadBytes(null);
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  late BenchFixture f;
  late WorkshopController controller;
  setUp(() async {
    f = BenchFixture(
      TestBenchStore(),
      BenchDefinition.fromSnapshot(
        File(BenchDefinition.asset).readAsStringSync(),
      ),
    );
    await f.init();
    controller = WorkshopController(
      f.gateway,
      fixtures.Runner(),
      MemoryEvidence(),
      provisioner: f.usbRunner,
      benchFactory: f.session,
    );
  });
  Future<void> show(WidgetTester t) async {
    await t.binding.setSurfaceSize(const Size(1200, 900));
    addTearDown(() => t.binding.setSurfaceSize(null));
    await fixtures.signIn(controller);
    await t.pumpWidget(
      RepaintBoundary(
        key: const ValueKey('bench-screen'),
        child: WorkshopApp(controller: controller),
      ),
    );
    await t.pumpAndSettle();
    await t.tap(find.text('Test bench'));
    await t.pumpAndSettle();
  }

  Future<void> tap(WidgetTester t, String text) async {
    final item = find.text(text).last;
    await t.ensureVisible(item);
    await t.tap(item);
    await t.pumpAndSettle();
  }

  Future<void> input(WidgetTester t, String field, String text) async {
    final item = find.widgetWithText(TextField, field);
    await t.ensureVisible(item);
    await t.enterText(item, text);
    await t.pump();
  }

  for (final error in [SessionExpired(), OperatorDenied()]) {
    test(
      'lost operator access during bench action clears the session ${error.runtimeType}',
      () async {
        await fixtures.signIn(controller);
        await controller.enterBench();
        await controller.benchAction((_) async => throw error);
        expect(controller.access, Access.denied);
        expect(controller.bench, isNull);
      },
    );
  }
  testWidgets(
    'selected device can reopen shared steps and verify an attachment',
    (t) async {
      final digest = benchHash('{}');
      final remote = {
        'header': {
          'id': 'shared-remote',
          'operator': fixtures.actor,
          'started_at': '2026-11-20',
          'participants': [
            {'device_id': f.registry.devices.single.id},
          ],
        },
        'result': {
          'generation': 1,
          'outcome': 'Interrupted',
          'steps': [
            {
              'number': 4,
              'actor': 'runner',
              'status': 'Incomplete',
              'evidence': 'Interrupted USB read',
            },
          ],
          'artifacts': [
            {
              'step': 4,
              'type': 'application/json',
              'bytes': 2,
              'sha256': digest,
            },
          ],
        },
      };
      bool verified = false;
      f.sync = BenchSync(
        (a, n, p) async {
          switch (n) {
            case 'workshop_test_runs':
              return [remote];
            case 'workshop_read_test_artifact':
              return base64Encode(utf8.encode('{}'));
            case 'workshop_test_definitions':
              return [
                {
                  'test_key': f.definition.guide['key'],
                  'revision': 1,
                  'definition_sha256': BenchDefinition.digest,
                  'snapshot': f.definition.snapshot,
                },
              ];
            case 'workshop_submit_test_run':
              return p['p_result']['generation'];
            case 'workshop_test_artifacts':
              return [];
          }
          throw StateError(n);
        },
        (_) async => verified,
        (_) async {
          verified = true;
        },
      );
      await show(t);
      await tap(t, 'Load shared history');
      await tap(t, 'Interrupted · 2026-11-20');
      await tap(t, 'Read step 4 attachment · 2 bytes');
      expect(find.text('{}'), findsOneWidget);
      await tap(t, 'Start guided test');
      await controller.cancelBench();
      await t.pumpAndSettle();
      await tap(t, 'Sync saved attempt');
      expect(find.textContaining('Server verified'), findsOneWidget);
    },
  );
  testWidgets(
    'from sidebar through guide, USB read, physical observation, export and retained history',
    (t) async {
      await show(t);
      await tap(t, 'Prerequisites and tester guide');
      expect(
        find.textContaining('runner · Save the started attempt'),
        findsOneWidget,
      );
      await tap(t, 'Prerequisites and tester guide');
      await tap(t, 'Start guided test');
      expect(f.seenDiscovery, isFalse);
      await tap(t, 'USB connected · read identity');
      expect(find.text('USB readback · D000000000001'), findsOneWidget);
      await input(t, 'Observed label serial', 'D000000000001');
      await tap(t, 'Save observation');
      await input(t, 'Export folder', 'example');
      await tap(t, 'Export report');
      expect(find.text('Exported to test/export.json'), findsOneWidget);
      expect(find.text('Tester observation · D000000000001'), findsOneWidget);
      final id = controller.bench!.report!['id'] as String;
      await tap(t, 'Devices');
      await tap(t, 'Test bench');
      await tap(t, id);
      expect(controller.bench!.report!['outcome'], 'Passed');
      await tap(t, 'Run again · new attempt');
      expect(controller.bench!.report!['prior_attempt'], id);
      await tap(t, 'Cancel attempt');
      expect(controller.bench!.report!['outcome'], 'Cancelled');
      await tap(t, 'Report details');
      expect(find.textContaining('definition_snapshot'), findsWidgets);
    },
  );
  testWidgets(
    'save recovery, unavailable label, reread and review are available from the current step',
    (t) async {
      await show(t);
      f.store.failGeneration = 1;
      await tap(t, 'Start guided test');
      expect(find.textContaining('disk full'), findsWidgets);
      f.store.failGeneration = null;
      await tap(t, 'Retry local save');
      f.store.failGeneration = 2;
      await tap(t, 'USB connected · read identity');
      f.store.failGeneration = null;
      await tap(t, 'Retry local save');
      await tap(t, 'Read identity');
      await tap(t, 'Label unavailable');
      await input(t, 'Reason label is unavailable', 'smudged');
      await tap(t, 'Save observation');
      expect(controller.bench!.report!['outcome'], 'Incomplete');
      await tap(t, 'Run again · new attempt');
      await tap(t, 'USB connected · read identity');
      f.store.wrongRead = true;
      await input(t, 'Observed label serial', 'D000000000001');
      await tap(t, 'Save observation');
      f.store.wrongRead = false;
      await tap(t, 'Verify reopened report');
      expect(controller.bench!.next, 7);
      await t.binding.setSurfaceSize(const Size(640, 850));
      await t.pumpAndSettle();
      expect(find.text('Export report').last, findsOneWidget);
    },
  );
  test('logout during late read is isolated and earlier attempt remains reviewable', () async {
    await fixtures.signIn(controller);
    await controller.enterBench();
    await controller.benchAction(f.start);
    final session = controller.bench!;
    f.response = Completer<Json>();
    final held = controller.benchAction(f.connected);
    while (!f.seenRead) {
      await Future<void>.delayed(Duration.zero);
    }
    final logout = controller.signOut();
    expect(controller.access, Access.signedOut);
    f.response!.complete({'late': true});
    await held;
    await logout;
    expect(session.report!['outcome'], 'Interrupted');
    expect(controller.bench, isNull);
    await fixtures.signIn(controller);
    await controller.enterBench();
    expect(controller.bench!.history.single['outcome'], 'Interrupted');
    controller.dispose();
    await controller.closed;
  });
  test(
    'failed cancellation save can be retried without losing evidence',
    () async {
      await fixtures.signIn(controller);
      await controller.enterBench();
      await controller.benchAction(f.start);
      f.store.failGeneration = 2;
      await controller.cancelBench();
      expect(controller.message, contains('Local evidence save failed'));
      f.store.failGeneration = null;
      await controller.benchAction((s) => s.retrySave());
      expect(controller.bench!.report!['outcome'], 'Cancelled');
      controller.dispose();
      await controller.closed;
    },
  );
  test('account change invalidates the open private bench', () async {
    await fixtures.signIn(controller);
    await controller.enterBench();
    await controller.benchAction(f.start);
    final record = controller.bench!;
    f.gateway.account = fixtures.other;
    await controller.benchAction((_) async => fail('Wrong account admitted'));
    expect(controller.access, Access.denied);
    expect(controller.bench, isNull);
    expect(record.report!['outcome'], 'Interrupted');
    controller.dispose();
    await controller.closed;
  });

  testWidgets(
    'device selection, blocked USB and history after a registry change and new sign-in',
    (t) async {
      f.gateway.loadOverride = () => Registry.fromJson({
        'articles': [
          {
            'id': fixtures.revision,
            'article_id': 'article',
            'role': 'Link',
            'name': 'Synthetic',
            'code': 'TEST',
            'revision': 1,
            'parts': [],
            'case_version': 'A',
          },
        ],
        'devices': [
          for (final n in [1, 2])
            {
              'id': '30000000-0000-4000-8000-00000000000$n',
              'serial': 'D00000000000$n',
              'article_revision_id': fixtures.revision,
              'provisioning_state': 'provisioned',
              'hardware_uid': '123456780000000$n',
            },
        ],
        'runs': [],
      });
      await show(t);
      await t.tap(find.byType(DropdownButton<String>));
      await t.pumpAndSettle();
      await tap(t, 'D000000000002');
      await tap(t, 'Start guided test');
      await tap(t, 'USB connected · read identity');
      expect(controller.bench!.report!['outcome'], 'Blocked');
      expect(
        find.textContaining('registry binding is unavailable'),
        findsOneWidget,
      );
      final id = controller.bench!.report!['id'] as String;
      f.gateway.loadOverride = null;
      f.gateway.completed = false;
      await controller.refresh();
      await t.pumpAndSettle();
      expect(
        find.text('A provisioned registry device is required.'),
        findsOneWidget,
      );
      await tap(t, id);
      expect(controller.bench!.report!['device']['serial'], 'D000000000002');
      await controller.action(() async => throw SessionExpired());
      await t.pumpAndSettle();
      await fixtures.signIn(controller);
      await t.pumpAndSettle();
      await tap(t, 'Open test bench');
      expect(find.text('Device history'), findsOneWidget);
    },
  );
  testWidgets('guided identity action matches Workshop design', (t) async {
    await show(t);
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · read identity');
    await expectLater(
      find.byKey(const ValueKey('bench-screen')),
      matchesGoldenFile('goldens/bench-identity-guide.png'),
    );
  });
}
