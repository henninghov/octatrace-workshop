import 'dart:io';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/claimed_update.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/claimed_update_panel.dart';
import 'package:octatrace_workshop/ui/provisioning_panel.dart';

import 'claimed_update_test.dart' as fixture;
import 'ui_flow_test.dart' show MemoryEvidence;
import 'widget_test.dart' as widget_fixture;

class UpdateStore implements ClaimedUpdateStore {
  final events = <String>[];
  Json? prior;
  @override
  Future<Json?> pendingUpdate(String account, String hardware) async => prior;
  @override
  Future<void> beginUpdate(Json record) async => events.add(record['phase']);
  @override
  Future<void> saveUpdate(Json record) async => events.add(record['phase']);
  @override
  Future<String> exportUpdate(Json record, String folder) async =>
      '$folder/synthetic.json';
  @override
  Future<void> releaseUpdate(Json record) async => events.add('released');
}

void main() {
  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final font = FontLoader('Excon')
      ..addFont(rootBundle.load('assets/fonts/Excon-Regular.otf'))
      ..addFont(rootBundle.load('assets/fonts/Excon-Medium.otf'));
    await font.load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  for (final version in [1, 2]) {
    testWidgets(
      'claimed CORE update guide $version shows the target before confirming and after verification',
      (t) async {
        final gateway = fixture.Gateway();
        final runner = fixture.Runner();
        final store = UpdateStore();
        final definition = BenchDefinition.fromSnapshot(
          File(BenchDefinition.inspectionAsset).readAsStringSync(),
        );
        final guide = File(
          'assets/bench/claimed-firmware-update.v$version.json',
        ).readAsStringSync();
        final guideData = jsonDecode(guide) as Map<String, dynamic>;
        runner.buildSource = guideData['after_source'] as String;
        runner.buildArtifact = guideData['after_artifact'] as String;
        final controller = WorkshopController(
          gateway,
          widget_fixture.Runner(),
          MemoryEvidence(),
          provisioner: runner,
          claimedUpdateFactory: (account, device, article, current) =>
              ClaimedUpdateSession(
                account: account,
                device: device,
                article: article,
                current: current,
                gateway: gateway,
                runner: runner,
                store: store,
                definition: definition,
                guideSnapshot: guide,
                now: () => DateTime.utc(2026, 11, 22),
                workshopFingerprint: () async => 'f' * 64,
                newId: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                prove: (account, selection, definition) async => {
                  ...selection,
                  'build': selection['source'],
                  'state': 'ready',
                  'busy': false,
                  'failed': false,
                  'public_key': fixture.key,
                  'challenge': 'c' * 64,
                  'signature': 'd' * 128,
                  'boot': selection['source'] == guideData['before_source']
                      ? 'a' * 32
                      : 'b' * 32,
                },
              ),
        )..access = Access.ready;
        await t.binding.setSurfaceSize(const Size(1100, 900));
        addTearDown(() => t.binding.setSurfaceSize(null));
        await t.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.dark, fontFamily: 'Excon'),
            home: Scaffold(
              body: SingleChildScrollView(
                child: ClaimedUpdatePanel(
                  controller: controller,
                  device: fixture.device,
                  article: fixture.article,
                ),
              ),
            ),
          ),
        );
        expect(
          t
              .widget<FilledButton>(
                find.widgetWithText(
                  FilledButton,
                  'Verify CORE identity for update',
                ),
              )
              .onPressed,
          isNull,
        );
        await t.tap(find.byType(CheckboxListTile));
        await t.pumpAndSettle();
        await t.tap(find.text('Verify CORE identity for update'));
        await t.pumpAndSettle();
        expect(find.textContaining('Identity verified.'), findsOneWidget);
        expect(runner.commands, ['inventory']);
        runner.mode = 'bootloader';
        await t.tap(find.text('Review firmware update'));
        await t.pumpAndSettle();
        expect(find.text('Confirm CORE firmware update'), findsOneWidget);
        expect(
          find.textContaining(
            'CORE build ${runner.buildSource.substring(0, 8)}',
          ),
          findsOneWidget,
        );
        await t.tap(find.text('Keep unchanged'));
        await t.pumpAndSettle();
        expect(runner.commands, ['inventory']);
        await t.tap(find.text('Review firmware update'));
        await t.pumpAndSettle();
        await t.tap(find.text('Confirm firmware update'));
        await t.pumpAndSettle();
        expect(find.text('Update successful'), findsOneWidget);
        expect(
          find.text(
            'CORE build ${runner.buildSource.substring(0, 8)} is running.',
          ),
          findsOneWidget,
        );
        expect(
          find.textContaining('original identity and claim were verified'),
          findsOneWidget,
        );
        if (version == 1) {
          await expectLater(
            find.byKey(const ValueKey('claimed-update-success')),
            matchesGoldenFile('goldens/claimed-update-success-dark.png'),
          );
        }
        await t.ensureVisible(find.text('Update report'));
        await t.tap(find.text('Update report'));
        await t.pumpAndSettle();
        await t.enterText(
          find.widgetWithText(TextField, 'Export folder'),
          '/tmp',
        );
        await t.ensureVisible(find.text('Export update report'));
        await t.tap(find.text('Export update report'));
        await t.pumpAndSettle();
        expect(find.text('Exported to /tmp/synthetic.json'), findsOneWidget);
        expect(runner.commands, ['inventory', 'inventory', 'install']);
        expect(
          store.events,
          containsAllInOrder([
            'preflight',
            'awaiting_bootloader',
            'write_started',
            'awaiting_postflight',
            'verified',
            'released',
          ]),
        );
        controller.dispose();
      },
    );
  }
  for (final scenario in ['cancel', 'interrupted', 'prior']) {
    testWidgets(
      'claimed update $scenario remains visible and does not silently repeat',
      (t) async {
        final gateway = fixture.Gateway();
        final runner = fixture.Runner();
        final store = UpdateStore();
        final definition = BenchDefinition.fromSnapshot(
          File(BenchDefinition.inspectionAsset).readAsStringSync(),
        );
        final guide = File('assets/bench/claimed-firmware-update.v1.json')
            .readAsStringSync();
        if (scenario == 'prior') {
          store.prior = {
            'id': 'synthetic',
            'phase': 'write_started',
            'before_source': fixture.oldSource,
            'after_source': fixture.newSource,
          };
        }
        final controller = WorkshopController(
          gateway,
          widget_fixture.Runner(),
          MemoryEvidence(),
          provisioner: runner,
          claimedUpdateFactory: (account, device, article, current) =>
              ClaimedUpdateSession(
                account: account,
                device: device,
                article: article,
                gateway: gateway,
                runner: runner,
                store: store,
                definition: definition,
                guideSnapshot: guide,
                newId: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                current: current,
                now: () => DateTime.utc(2026),
                workshopFingerprint: () async => 'f' * 64,
                prove: (account, selection, definition) async => {
                  ...selection,
                  'build': selection['source'],
                  'state': 'ready',
                  'busy': false,
                  'failed': false,
                  'boot': 'a' * 32,
                  'challenge': 'c' * 64,
                  'signature': 'd' * 128,
                },
              ),
        )..access = Access.ready;
        await t.binding.setSurfaceSize(const Size(1100, 900));
        addTearDown(() => t.binding.setSurfaceSize(null));
        await t.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: SingleChildScrollView(
                child: ClaimedUpdatePanel(
                  controller: controller,
                  device: fixture.device,
                  article: fixture.article,
                ),
              ),
            ),
          ),
        );
        await t.tap(find.byType(CheckboxListTile));
        await t.pumpAndSettle();
        await t.tap(find.text('Verify CORE identity for update'));
        await t.pumpAndSettle();
        if (scenario == 'prior') {
          expect(
            find.textContaining('previous update is unresolved'),
            findsOneWidget,
          );
          expect(runner.commands, isEmpty);
          await t.ensureVisible(find.text('Update report'));
          expect(find.text('Update report'), findsOneWidget);
        } else if (scenario == 'cancel') {
          await t.tap(find.text('Cancel before update'));
          await t.pumpAndSettle();
          expect(store.events, contains('cancelled_before_write'));
          expect(runner.commands.where((x) => x == 'install'), isEmpty);
        } else {
          runner.mode = 'bootloader';
          runner.installFailure = StateError('interrupted');
          await t.tap(find.text('Review firmware update'));
          await t.pumpAndSettle();
          await t.tap(find.text('Confirm firmware update'));
          await t.pumpAndSettle();
          expect(find.textContaining('Update needs review'), findsOneWidget);
          expect(find.text('Review firmware update'), findsNothing);
          expect(store.events, contains('interrupted_after_write'));
          expect(store.events, isNot(contains('released')));
        }
        expect(find.text('Update successful'), findsNothing);
        controller.dispose();
      },
    );
  }
  testWidgets(
    'claimed CORE opens the update controls rather than provisioning',
    (t) async {
      final gateway = fixture.Gateway();
      final controller = WorkshopController(
        gateway,
        widget_fixture.Runner(),
        MemoryEvidence(),
        claimedUpdateFactory: (account, device, article, current) =>
            throw StateError('not started'),
      )..access = Access.ready;
      await t.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ProvisioningPanel(
              controller: controller,
              device: fixture.device,
              article: fixture.article,
            ),
          ),
        ),
      );
      expect(find.byType(ClaimedUpdatePanel), findsOneWidget);
      expect(find.text('Verify CORE identity for update'), findsOneWidget);
      expect(find.text('Install and provision'), findsNothing);
      controller.dispose();
    },
  );
}
