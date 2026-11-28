import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show SynchronousFuture;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/bench_sync.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'support/bench_fixture.dart' show BenchFixture, TestBenchStore;
import 'support/firmware_checks_fixture.dart';
import 'ui_flow_test.dart' show MemoryEvidence;
import 'widget_test.dart' as fixtures;

class BenchGuideAssets extends CachingAssetBundle {
  final Map<String, Future<String>> guides = {
    for (final file in [
      'assets/bench/c841-phone-link-discovery.v1.txt',
      'assets/bench/c842-phone-link-identity.v1.txt',
      'assets/bench/c843-phone-link-proof.v1.txt',
      'assets/bench/c843-phone-link-proof.v2.txt',
      'assets/bench/c845-physical-link-claim.v1.txt',
    ])
      file: SynchronousFuture(File(file).readAsStringSync()),
  };

  @override
  Future<ByteData> load(String key) => rootBundle.load(key);

  @override
  Future<String> loadString(String key, {bool cache = true}) =>
      guides[key] ?? rootBundle.loadString(key, cache: cache);
}

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
        child: DefaultAssetBundle(
          bundle: BenchGuideAssets(),
          child: WorkshopApp(controller: controller),
        ),
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

  testWidgets(
    'supervised proof guide requires both phone signatures and registry readback',
    (t) async {
      await show(t);
      await tap(t, 'Verify both signing keys over supervised USB · revision 2');
      expect(find.textContaining('Both signatures verified'), findsOneWidget);
      expect(find.textContaining('fresh Unclaimed readback'), findsOneWidget);
      expect(
        find.textContaining('End before claim completion'),
        findsOneWidget,
      );
      expect(controller.bench!.report, isNull);
    },
  );

  testWidgets(
    'first-claim guide distinguishes clock refusal and signed proof',
    (t) async {
      await show(t);
      await tap(t, 'Verify the iPhone and LINK signing keys · revision 1');
      expect(
        find.textContaining('An unknown bound permits a refusal test'),
        findsOneWidget,
      );
      expect(find.textContaining('Both signatures verified'), findsOneWidget);
      expect(find.textContaining('before claim completion'), findsOneWidget);
      expect(controller.bench!.report, isNull);
    },
  );

  testWidgets(
    'physical LINK claim guide covers restart and the ownership assignment',
    (t) async {
      await show(t);
      await tap(t, 'Claim one physical LINK from the iPhone · revision 1');
      expect(find.textContaining('Tap Claim LINK once'), findsOneWidget);
      expect(find.textContaining('Fully close and reopen'), findsOneWidget);
      expect(find.textContaining('one ownership assignment'), findsOneWidget);
      expect(controller.bench!.report, isNull);
    },
  );

  testWidgets('phone discovery guide identifies both device confirmations', (
    t,
  ) async {
    await show(t);
    await tap(t, 'Phone to LINK discovery guide · revision 1');
    expect(find.textContaining('setup control subscribed'), findsOneWidget);
    expect(find.textContaining('setup record subscribed'), findsOneWidget);
    expect(controller.bench!.report, isNull);
  });

  testWidgets(
    'local LINK identity guide includes the scan and reconnect evidence',
    (t) async {
      await show(t);
      await tap(t, 'Verify scanned LINK identity · revision 1');
      expect(find.textContaining('Identity verified'), findsOneWidget);
      expect(
        find.textContaining('sameBoot=true freshNonce=true'),
        findsOneWidget,
      );
      expect(controller.bench!.report, isNull);
    },
  );

  testWidgets(
    'firmware host controls are integrated into the signed-in bench',
    (t) async {
      final checks = FakeFirmwareChecks();
      controller = WorkshopController(
        f.gateway,
        fixtures.Runner(),
        MemoryEvidence(),
        provisioner: f.usbRunner,
        benchFactory: f.session,
        firmwareChecks: checks,
        firmwareRoot: '/firmware',
        firmwarePython: '/python',
        firmwareFonts: '/fonts',
      );
      await show(t);
      await tap(t, 'Firmware host regression tests');
      expect(find.text('Firmware checkout folder'), findsOneWidget);
      await t.ensureVisible(find.text('Run firmware tests'));
      await t.tap(find.text('Run firmware tests'));
      await t.pump();
      expect(checks.account, f.gateway.accountId);
      checks.pending!.complete(checks.reports.first);
      await t.pumpAndSettle();
      expect(find.text('Status: passed'), findsOneWidget);
      await controller.signOut();
      await t.pumpAndSettle();
      expect(checks.cancels, greaterThan(0));
    },
  );

  testWidgets(
    'permanent handshake presents the other registered board before USB runs',
    (t) async {
      f.paired = BenchDefinition.fromSnapshot(
        File(BenchDefinition.pairedAsset).readAsStringSync(),
      );
      f.gateway.loadOverride = () => Registry.fromJson({
        'runs': <Json>[],
        'articles': [
          for (final r in ['Link', 'Core'])
            {
              'id': 'revision-$r',
              'article_id': 'article-$r',
              'code': r,
              'name': r,
              'role': r,
              'revision': 1,
              'case_version': 'A',
              'parts': <Json>[],
            },
        ],
        'devices': [
          for (final (i, r) in ['Link', 'Core'].indexed)
            {
              'id': 'device-$r',
              'serial': 'D00000000000${i + 1}',
              'article_revision_id': 'revision-$r',
              'provisioning_state': 'provisioned',
              'hardware_uid': '123456780000000${i + 1}',
            },
        ],
      });
      await show(t);
      await t.tap(find.byType(DropdownButton<BenchDefinition>));
      await t.pumpAndSettle();
      await tap(t, f.paired!.guide['title']);
      await tap(t, 'Start guided test');
      expect(find.text('Bench peer'), findsOneWidget);
      expect(find.text('D000000000002'), findsWidgets);
      expect(
        find.text('Both boards connected · run handshake'),
        findsOneWidget,
      );
      expect(f.seenDiscovery, isFalse);
    },
  );
  for (final mode in ['install', 'stop', 'prepare']) {
    testWidgets(
      '$mode shows a separate enabled confirmation during the running action',
      (t) async {
        f.installation = BenchDefinition.fromSnapshot(
          File(BenchDefinition.installationAsset).readAsStringSync(),
        );
        f.intentStop = BenchDefinition.fromSnapshot(
          File(BenchDefinition.intentStopAsset).readAsStringSync(),
        );
        f.preparation = BenchDefinition.fromSnapshot(
          File(BenchDefinition.preparationAsset).readAsStringSync(),
        );
        var writes = 0;
        f.installReader =
            (a, r, k, credential, id, fault, confirm, {onDiagnostic}) async {
              final answer = await confirm({
                'review_token': 'aa' * 32,
                'expires_ms': 25000,
                'review': {
                  'serial': r.device.serial,
                  'role': r.build.role,
                  'credential_revision': 1,
                  'envelope_sha256': credential.digest,
                  'journal_state': 'empty',
                  'slots_used': 0,
                  'fault': fault,
                },
              });
              if (answer['confirm'] != true) throw BenchCancelled();
              writes++;
              return {
                'installation_proof': {
                  'journal_state': fault == 1 ? 'pending' : 'ready',
                },
              };
            };
        f.preparationReader = (a, r, k, id, confirm, {onDiagnostic}) async {
          final answer = await confirm({
            'review_token': 'aa' * 32,
            'expires_ms': 25000,
            'inspection': {
              'identity_proof': {'serial': r.device.serial},
              'role': r.build.role,
              'sha256': 'dd' * 32,
            },
          });
          if (answer['confirm'] != true) throw BenchCancelled();
          writes++;
          return {
            'preparation_result': {'state': 'blank'},
          };
        };
        await show(t);
        final definition = mode == 'prepare'
            ? f.preparation!
            : mode == 'stop'
            ? f.intentStop!
            : f.installation!;
        await t.tap(find.byType(DropdownButton<BenchDefinition>));
        await t.pumpAndSettle();
        await t.tap(find.text(definition.guide['title']).last);
        await t.pumpAndSettle();
        await tap(t, 'Start guided test');
        final connect = find.text(
          mode == 'prepare'
              ? 'USB connected · inspect for preparation'
              : 'USB connected · verify for installation',
        );
        await t.ensureVisible(connect);
        await t.tap(connect);
        await t.pump();
        await t.pump(const Duration(milliseconds: 50));
        expect(controller.busy, true);
        expect(writes, 0);
        final confirm = find.widgetWithText(
          FilledButton,
          mode == 'prepare'
              ? 'Confirm preparation'
              : mode == 'stop'
              ? 'Confirm controlled stop'
              : 'Confirm installation',
        );
        await t.ensureVisible(confirm);
        expect(t.widget<FilledButton>(confirm).onPressed, isNotNull);
        await t.tap(confirm);
        await t.pumpAndSettle();
        expect(writes, 1);
        expect(controller.bench!.report!['steps'][3]['status'], 'Passed');
        expect(
          find.textContaining(
            mode == 'prepare'
                ? 'Preparation result · blank'
                : mode == 'stop'
                ? 'Installation result · pending'
                : 'Installation result · ready',
          ),
          findsOneWidget,
        );
      },
    );
  }

  testWidgets(
    'confirmation cancellation remains incomplete and no-session approval is harmless',
    (t) async {
      await controller.confirmBenchInstallation(true);
      f.installation = BenchDefinition.fromSnapshot(
        File(BenchDefinition.installationAsset).readAsStringSync(),
      );
      f.installReader =
          (a, r, k, credential, id, fault, confirm, {onDiagnostic}) async {
            final answer = await confirm({
              'review_token': 'aa' * 32,
              'expires_ms': 25000,
              'review': {
                'serial': r.device.serial,
                'role': 'Link',
                'credential_revision': 1,
                'envelope_sha256': credential.digest,
                'journal_state': 'empty',
                'slots_used': 0,
                'fault': 0,
              },
            });
            expect(answer['confirm'], false);
            throw BenchCancelled();
          };
      await show(t);
      await t.tap(find.byType(DropdownButton<BenchDefinition>));
      await t.pumpAndSettle();
      await t.tap(find.text(f.installation!.guide['title']).last);
      await t.pumpAndSettle();
      await tap(t, 'Start guided test');
      final connect = find.text('USB connected · verify for installation');
      await t.ensureVisible(connect);
      await t.tap(connect);
      await t.pump();
      await t.pump(const Duration(milliseconds: 50));
      await tap(t, 'Cancel installation');
      expect(controller.bench!.report!['outcome'], 'Incomplete');
      await controller.confirmBenchInstallation(true);
      expect(controller.message, contains('confirmation stopped'));
    },
  );

  testWidgets('inspection guide uses the same durable guided flow', (t) async {
    f.inspection = BenchDefinition.fromSnapshot(
      File(BenchDefinition.inspectionAsset).readAsStringSync(),
    );
    await show(t);
    await t.tap(find.byType(DropdownButton<BenchDefinition>));
    await t.pumpAndSettle();
    await t.tap(find.text('Inspect the credential reservation').last);
    await t.pumpAndSettle();
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · inspect storage');
    expect(find.textContaining('Storage · blank · SHA-256'), findsOneWidget);
    await input(t, 'Observed storage classification', 'blank');
    await tap(t, 'Save observation');
    expect(controller.bench!.report!['steps'][4]['status'], 'Passed');
    expect(controller.bench!.report!['steps'][5]['status'], 'Passed');
  });

  testWidgets('readiness guide records the startup state', (t) async {
    f.readiness = BenchDefinition.fromSnapshot(
      File(BenchDefinition.readinessAsset).readAsStringSync(),
    );
    var reads = 0;
    f.readinessReader = (account, selection, key, {onDiagnostic}) async => {
      'state': 'empty',
      'boot': ++reads == 1 ? 'aa' * 16 : 'bb' * 16,
      'inspection': {'state': 'blank', 'sha256': '22' * 32},
    };
    await show(t);
    await t.tap(find.byType(DropdownButton<BenchDefinition>));
    await t.pumpAndSettle();
    await t.tap(find.text('Check credential readiness at startup').last);
    await t.pumpAndSettle();
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · check readiness');
    expect(
      find.textContaining('Readiness · empty · Storage blank'),
      findsOneWidget,
    );
    await tap(t, 'I restarted the device normally');
    await tap(t, 'Check after restart');
    expect(controller.bench!.report!['steps'][4]['status'], 'Passed');
    expect(controller.bench!.report!['steps'][5]['status'], 'Passed');
  });

  testWidgets(
    'credential delivery shows verified result and records observation',
    (t) async {
      f.delivery = BenchDefinition.fromSnapshot(
        File(BenchDefinition.deliveryAsset).readAsStringSync(),
      );
      await show(t);
      await t.tap(find.byType(DropdownButton<BenchDefinition>));
      await t.pumpAndSettle();
      await t.tap(find.text('Verify a factory credential on the device').last);
      await t.pumpAndSettle();
      await tap(t, 'Start guided test');
      await tap(t, 'USB connected · verify credential');
      expect(
        find.textContaining('Credential verification · verified'),
        findsOneWidget,
      );
      await input(t, 'Observed verification result', 'verified');
      await tap(t, 'Save observation');
      expect(controller.bench!.report!['steps'][4]['status'], 'Passed');
      expect(controller.bench!.report!['steps'][5]['status'], 'Passed');
    },
  );

  testWidgets('recorded log filters use the saved steps', (t) async {
    await show(t);
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · read identity');
    expect(
      find.textContaining('Step 1 · Select device · Passed'),
      findsOneWidget,
    );
    expect(
      find.textContaining('Step 2 · Save attempt · Passed'),
      findsOneWidget,
    );
    await t.ensureVisible(find.byKey(const ValueKey('bench-log-source')));
    await t.tap(find.byKey(const ValueKey('bench-log-source')));
    await t.pumpAndSettle();
    await t.tap(find.text('Runner').last);
    await t.pumpAndSettle();
    expect(
      find.textContaining('Step 1 · Select device · Passed'),
      findsNothing,
    );
    expect(
      find.textContaining('Step 2 · Save attempt · Passed'),
      findsOneWidget,
    );
    await t.tap(find.byKey(const ValueKey('bench-log-scope')));
    await t.pumpAndSettle();
    await t.tap(find.text('Current step').last);
    await t.pumpAndSettle();
    expect(find.text('No recorded steps for this selection.'), findsOneWidget);
    await tap(t, 'Device history');
    expect(find.text('Recorded attempts'), findsOneWidget);
  });

  testWidgets('unknown device role is visible and cannot start a test', (
    t,
  ) async {
    f.inspection = BenchDefinition.fromSnapshot(
      File(BenchDefinition.inspectionAsset).readAsStringSync(),
    );
    f.gateway.loadOverride = () => Registry.fromJson({
      'articles': <Object>[],
      'devices': [
        {
          'id': fixtures.device,
          'serial': 'D000000000001',
          'article_revision_id': fixtures.revision,
          'provisioning_state': 'provisioned',
          'hardware_uid': '1234567800000001',
        },
      ],
      'runs': <Object>[],
    });
    await show(t);
    expect(find.textContaining('Unknown role'), findsOneWidget);
    expect(
      find.textContaining('no matching article, role or compatible build'),
      findsOneWidget,
    );
    expect(find.text('Start guided test'), findsNothing);
    await t.tap(find.text('Light mode'));
    await t.pumpAndSettle();
    await t.binding.setSurfaceSize(const Size(1400, 1100));
    await t.pumpAndSettle();
    await expectLater(
      find.byKey(const ValueKey('bench-screen')),
      matchesGoldenFile('goldens/bench-unknown-role-light.png'),
    );
    await t.binding.setSurfaceSize(const Size(640, 850));
    await t.pumpAndSettle();
    expect(t.takeException(), isNull);
  });

  testWidgets('dark inspection guide matches the reviewed desktop layout', (
    t,
  ) async {
    f.inspection = BenchDefinition.fromSnapshot(
      File(BenchDefinition.inspectionAsset).readAsStringSync(),
    );
    await show(t);
    await t.binding.setSurfaceSize(const Size(1400, 1100));
    await t.pumpAndSettle();
    expect(find.text('Light mode'), findsOneWidget);
    await t.tap(find.byType(DropdownButton<BenchDefinition>));
    await t.pumpAndSettle();
    await t.tap(find.text('Inspect the credential reservation').last);
    await t.pumpAndSettle();
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · inspect storage');
    await t.drag(
      find.byType(SingleChildScrollView).first,
      const Offset(0, 1800),
    );
    await t.pumpAndSettle();
    expect(find.text('One step at a time.'), findsOneWidget);
    expect(find.text('Recorded logs'), findsOneWidget);
    await expectLater(
      find.byKey(const ValueKey('bench-screen')),
      matchesGoldenFile('goldens/bench-inspection-dark.png'),
    );
  });

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
                  'revision': f.definition.guide['revision'],
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
      await t.tap(find.byKey(const ValueKey('bench-device-selector')));
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
    await t.tap(find.text('Light mode'));
    await t.pumpAndSettle();
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · read identity');
    await expectLater(
      find.byKey(const ValueKey('bench-screen')),
      matchesGoldenFile('goldens/bench-identity-guide.png'),
    );
  });
  testWidgets(
    'startup diagnostics selection and measured states appear in the bench',
    (t) async {
      f.startupDiagnostics = BenchDefinition.fromSnapshot(
        File(BenchDefinition.startupDiagnosticsAsset).readAsStringSync(),
      );
      f.startupDiagnosticsReader =
          (account, selection, key, check, {onDiagnostic}) async => {
            'selection': check,
            'outcome': 'passed',
            'error': null,
            'frame': {
              'results': [
                for (final name in BenchSession.startupChecks.skip(1))
                  {
                    'id': name,
                    'result': check == 'all' || check == name
                        ? 'passed'
                        : 'not_run',
                  },
              ],
            },
          };
      await show(t);
      await t.tap(find.byType(DropdownButton<BenchDefinition>).first);
      await t.pumpAndSettle();
      await t.tap(find.text('Run device startup diagnostics').last);
      await t.pumpAndSettle();
      await tap(t, 'Start guided test');
      await tap(t, 'USB connected · run diagnostics');
      expect(find.text('radio · passed'), findsOneWidget);
      await tap(t, 'I reviewed the results');
      expect(controller.bench!.report!['steps'][5]['status'], 'Passed');
    },
  );
  testWidgets('crypto probe selection displays measurements and review', (
    t,
  ) async {
    f.cryptoProbe = BenchDefinition.fromSnapshot(
      File(BenchDefinition.cryptoProbeAsset).readAsStringSync(),
    );
    f.cryptoProbeReader = (account, selection, key, {onDiagnostic}) async => {
      'outcome': 'passed',
      'frame': {
        'hash': true,
        'signature': true,
        'agreement': true,
        'random': true,
        'stack_free_words': 777,
      },
      'host_elapsed_ms': 42,
    };
    await show(t);
    await t.tap(find.byType(DropdownButton<BenchDefinition>).first);
    await t.pumpAndSettle();
    await t.tap(find.text('Run live crypto worker probe').last);
    await t.pumpAndSettle();
    await tap(t, 'Start guided test');
    await tap(t, 'USB connected · run diagnostics');
    expect(find.text('hash · true'), findsOneWidget);
    expect(find.textContaining('777 words'), findsOneWidget);
    await tap(t, 'I reviewed the results');
    expect(controller.bench!.report!['steps'][5]['status'], 'Passed');
  });
}
