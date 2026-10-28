import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/provisioning_panel.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'widget_test.dart' as f;
import 'ui_flow_test.dart' show MemoryEvidence;
import 'provisioning_test.dart' as p;
import 'identity_preparation_test.dart' show PreparationRunner;

import 'package:octatrace_workshop/domain/provisioning.dart';

class CoreCatalogueRunner extends p.SetupRunner {
  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    if (command == 'inventory') {
      return {
        'targets': [
          {...p.targetJson(), 'label': 'Synthetic T114 · app'},
          {
            ...p.targetJson('bootloader'),
            'label': 'Synthetic T114 · bootloader',
          },
        ],
        'builds': [
          p.buildJson(),
          {
            ...p.buildJson(),
            'role': 'Core',
            'label': '0.2.0 · CORE · aaaaaaaa',
          },
        ],
      };
    }
    return super.execute(
      account: account,
      command: command,
      parameters: parameters,
    );
  }
}

void main() {
  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final font = FontLoader('Excon')
      ..addFont(rootBundle.load('assets/fonts/Excon-Regular.otf'));
    font.addFont(rootBundle.load('assets/fonts/Excon-Medium.otf'));
    await font.load();
    await const SvgAssetLoader('assets/branding/wordmark.svg').loadBytes(null);
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  late p.SetupGateway gateway;
  late p.SetupRunner runner;
  late WorkshopController c;
  setUp(() {
    gateway = p.SetupGateway();
    runner = p.SetupRunner();
    c = WorkshopController(
      gateway,
      f.Runner(),
      MemoryEvidence(),
      provisioner: runner,
      idFactory: () => p.requestId,
    );
  });
  // These widget fixtures own no native resources. Do not await a close future
  // created in Flutter's fake clock from package:test's outer teardown zone.
  tearDown(() {
    c.dispose();
  });
  Future<void> show(WidgetTester t) async {
    await t.binding.setSurfaceSize(const Size(1300, 1100));
    addTearDown(() => t.binding.setSurfaceSize(null));
    await f.signIn(c);
    await t.pumpWidget(
      RepaintBoundary(
        key: const ValueKey('provisioning-golden'),
        child: WorkshopApp(controller: c),
      ),
    );
    await t.pumpAndSettle();
    await t.tap(find.byTooltip('Open device'));
    await t.pumpAndSettle();
  }

  Future<void> select(WidgetTester t, int index, String text) async {
    final dropdown = find.byType(DropdownButtonFormField<String>).at(index);
    await t.ensureVisible(dropdown);
    await t.tap(dropdown);
    await t.pumpAndSettle();
    await t.tap(find.text(text).last);
    await t.pumpAndSettle();
  }

  Future<void> choose(WidgetTester t, {String mode = 'app'}) async {
    await t.tap(find.text('Refresh USB and firmware'));
    await t.pumpAndSettle();
    await select(t, 1, 'Synthetic LINK · $mode');
    await select(t, 2, p.build.label);
  }

  void usePreparationRunner() {
    c.dispose();
    runner = PreparationRunner();
    c = WorkshopController(
      gateway,
      f.Runner(),
      MemoryEvidence(),
      provisioner: runner,
      idFactory: () => p.requestId,
    );
  }

  Color pillTextColor(WidgetTester t) => t
      .widget<Text>(
        find.descendant(
          of: find.byType(ProvisioningStatusPill),
          matching: find.byType(Text),
        ),
      )
      .style!
      .color!;
  testWidgets(
    'preparation can be declined and confirmed within the same workflow',
    (t) async {
      usePreparationRunner();
      await show(t);
      await choose(t);
      await t.tap(find.text('Verify and provision'));
      await t.pump();
      await t.pump(const Duration(milliseconds: 300));
      expect(find.text('Prepare identity storage'), findsOneWidget);
      expect(find.text('Synthetic board'), findsOneWidget);
      expect(find.text('PENDING'), findsOneWidget);
      await t.tap(find.text('Keep unchanged'));
      await t.pumpAndSettle();
      expect((runner as PreparationRunner).received, isNull);
      await t.tap(find.text('Verify and provision'));
      await t.pump();
      await t.pump(const Duration(milliseconds: 300));
      await t.tap(find.text('Prepare and continue'));
      await t.pumpAndSettle();
      expect(find.text('SUCCESSFUL'), findsOneWidget);
      expect(pillTextColor(t), const Color(0xff1b5e20));
      expect(c.readbackSaved, isTrue);
    },
  );
  testWidgets(
    'server pending failed and successful labels follow actual confirmation',
    (t) async {
      gateway.heldComplete = Completer<void>();
      await show(t);
      await choose(t);
      await t.tap(find.text('Verify and provision'));
      await t.pump();
      await t.pump(const Duration(milliseconds: 300));
      expect(find.text('PENDING'), findsOneWidget);
      expect(pillTextColor(t), const Color(0xffe65100));
      expect(find.text('SUCCESSFUL'), findsNothing);
      gateway.heldComplete!.completeError(StateError('offline'));
      await t.pumpAndSettle();
      expect(find.text('FAILED'), findsOneWidget);
      expect(pillTextColor(t), const Color(0xffb71c1c));
      expect(find.textContaining('Proof saved locally.'), findsOneWidget);
      gateway.heldComplete = null;
      await t.ensureVisible(find.text('Retry evidence upload'));
      await t.tap(find.text('Retry evidence upload'));
      await t.pumpAndSettle();
      expect(find.text('SUCCESSFUL'), findsOneWidget);
      expect(find.text('FAILED'), findsNothing);
      expect(find.text('PENDING'), findsNothing);
    },
  );
  testWidgets('USB failure has a red label before any proof exists', (t) async {
    runner.failure = const ProvisioningFailure('Device unavailable');
    await show(t);
    runner.failure = null;
    await choose(t);
    runner.failure = const ProvisioningFailure('Device unavailable');
    await t.tap(find.text('Verify and provision'));
    await t.pump();
    await t.pump(const Duration(milliseconds: 300));
    expect(find.text('FAILED'), findsOneWidget);
    expect(find.textContaining('review the diagnostic.'), findsOneWidget);
    expect(c.readback, isNull);
  });
  testWidgets('a disposed device panel cannot open a late preparation dialog', (
    t,
  ) async {
    usePreparationRunner();
    final prepare = runner as PreparationRunner;
    prepare.inspection = Completer<Json>();
    await show(t);
    await choose(t);
    await t.tap(find.text('Verify and provision'));
    await t.pump();
    await t.pump(const Duration(milliseconds: 300));
    await t.pumpWidget(const MaterialApp(home: SizedBox()));
    prepare.inspection!.complete(
      p.preparationJson(prepare.inspectParameters!, status: 'required'),
    );
    await t.pumpAndSettle();
    expect(prepare.received, isNull);
    expect(t.takeException(), isNull);
  });
  for (final dark in [false, true]) {
    testWidgets(
      'preparation dialog and successful label appearance ${dark ? 'dark' : 'light'}',
      (t) async {
        usePreparationRunner();
        await show(t);
        await choose(t);
        if (dark) {
          await t.tap(find.text('Dark mode'));
          await t.pumpAndSettle();
        }
        await t.tap(find.text('Verify and provision'));
        await t.pump();
        await t.pump(const Duration(milliseconds: 300));
        await expectLater(
          find.byType(AlertDialog),
          matchesGoldenFile(
            'goldens/storage-preparation-${dark ? 'dark' : 'light'}.png',
          ),
        );
        await t.tap(find.text('Prepare and continue'));
        await t.pumpAndSettle();
        await expectLater(
          find.byKey(const ValueKey('provisioning-golden')),
          matchesGoldenFile(
            'goldens/provisioning-success-${dark ? 'dark' : 'light'}.png',
          ),
        );
      },
      tags: 'golden',
    );
  }
  testWidgets(
    'existing device opens selectors; verify confirms registry and copyable details',
    (t) async {
      await show(t);
      expect(find.text('Registry device'), findsOneWidget);
      expect(find.textContaining('Connect LINK by USB'), findsOneWidget);
      expect(
        t
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Verify and provision'),
            )
            .onPressed,
        isNull,
      );
      await choose(t);
      await t.tap(find.text('Verify and provision'));
      await t.pumpAndSettle();
      expect(
        find.text('Provisioning confirmed by the server. Registry refreshed.'),
        findsOneWidget,
      );
      expect(c.registry!.devices.single.state, 'provisioned');
      await t.ensureVisible(find.text('Details'));
      await t.tap(find.text('Details'));
      await t.pumpAndSettle();
      expect(find.byTooltip('Copy Selected USB identity'), findsOneWidget);
      expect(find.byTooltip('Copy Firmware artifact'), findsOneWidget);
      expect(find.text('Verification evidence'), findsOneWidget);
      await select(t, 0, 'D000000000001 · provisioned');
      expect(t.takeException(), isNull);
    },
  );
  testWidgets(
    'completed bound device reopened without selection has no false hardware conflict',
    (t) async {
      await show(t);
      await choose(t);
      await t.tap(find.text('Verify and provision'));
      await t.pumpAndSettle();
      expect(c.registry!.devices.single.hardwareUid, p.hardware);
      await t.tap(find.text('Devices'));
      await t.pumpAndSettle();
      await t.tap(find.byTooltip('Open device'));
      await t.pumpAndSettle();
      expect(
        find.text('Provisioning confirmed by the server. Registry refreshed.'),
        findsOneWidget,
      );
      expect(find.textContaining('bound to another USB device'), findsNothing);
      expect(
        t
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Verify and provision'),
            )
            .onPressed,
        isNull,
      );
    },
  );
  testWidgets(
    'bootloader install keeps Cancel in flow and retains late proof on cancellation',
    (t) async {
      await show(t);
      await choose(t, mode: 'bootloader');
      runner.held = Completer();
      await t.tap(find.text('Install and provision'));
      await t.pump();
      await t.pump();
      expect(find.textContaining('Verifying identity and key'), findsOneWidget);
      expect(find.text('Cancel'), findsOneWidget);
      await t.tap(find.text('Cancel'));
      await t.pump();
      runner.held!.complete(p.proof());
      await t.pumpAndSettle();
      expect(c.message, contains('Provisioning stopped'));
      expect(find.text('Retry evidence upload'), findsOneWidget);
      await t.tap(find.text('Retry evidence upload'));
      await t.pumpAndSettle();
      expect(c.readbackSaved, isTrue);
      expect(gateway.completes, 1);
    },
  );
  testWidgets(
    'no USB or qualified build and stale selections cannot enable installation',
    (t) async {
      await show(t);
      runner.absent = true;
      await t.tap(find.text('Refresh USB and firmware'));
      await t.pumpAndSettle();
      expect(
        find.textContaining('No supported USB device found'),
        findsOneWidget,
      );
      expect(find.textContaining('No qualified LINK firmware'), findsOneWidget);
      runner.absent = false;
      await choose(t);
      runner.absent = true;
      await t.tap(find.text('Refresh USB and firmware'));
      await t.pumpAndSettle();
      expect(
        t
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Verify and provision'),
            )
            .onPressed,
        isNull,
      );
    },
  );
  testWidgets(
    'claimed devices and hardware mismatch have clear disabled guidance',
    (t) async {
      await f.signIn(c);
      await c.discoverUsb();
      Future<void> panel(Json change) async {
        final device = DeviceRecord.fromJson({
          'id': f.device,
          'serial': 'D000000000001',
          'article_revision_id': f.revision,
          'provisioning_state': 'reserved',
          ...change,
        });
        await t.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: SingleChildScrollView(
                child: ProvisioningPanel(
                  key: ValueKey(change.toString()),
                  controller: c,
                  device: device,
                  article: c.registry!.articles.single,
                ),
              ),
            ),
          ),
        );
        await t.pumpAndSettle();
      }

      await panel({'owner_user_id': f.other});
      expect(
        find.textContaining('unclaimed development LINK or CORE'),
        findsOneWidget,
      );
      await panel({'hardware_uid': '8765432100000001'});
      expect(find.textContaining('bound to another USB device'), findsNothing);
      await t.tap(find.byType(DropdownButtonFormField<String>).first);
      await t.pumpAndSettle();
      await t.tap(find.text('Synthetic LINK · app').last);
      await t.pumpAndSettle();
      expect(
        find.textContaining('bound to another USB device'),
        findsOneWidget,
      );
      expect(
        t
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Verify and provision'),
            )
            .onPressed,
        isNull,
      );
      expect(t.takeException(), isNull);
    },
  );
  for (final dark in [false, true]) {
    testWidgets(
      'provisioning selectors render in ${dark ? 'dark' : 'light'} appearance',
      (t) async {
        await show(t);
        await choose(t, mode: 'bootloader');
        // Exercise appearance switching before capturing a fully painted SVG.
        await t.tap(find.text('Dark mode'));
        await t.pumpAndSettle();
        if (!dark) {
          await t.tap(find.text('Light mode'));
          await t.pumpAndSettle();
        }
        await t.pump();
        await expectLater(
          find.byKey(const ValueKey('provisioning-golden')),
          matchesGoldenFile(
            'goldens/provisioning-${dark ? 'dark' : 'light'}.png',
          ),
        );
      },
      tags: 'golden',
    );
  }
  testWidgets(
    'CORE offers only CORE firmware and completes its existing reservation',
    (t) async {
      c.dispose();
      runner = CoreCatalogueRunner();
      gateway.product = 'Core';
      c = WorkshopController(
        gateway,
        f.Runner(),
        MemoryEvidence(),
        provisioner: runner,
        idFactory: () => p.requestId,
      );
      await show(t);
      expect(find.textContaining('Connect CORE by USB'), findsOneWidget);
      await t.tap(find.text('Refresh USB and firmware'));
      await t.pumpAndSettle();
      await select(t, 1, 'Synthetic T114 · app');
      final dropdown = find.byType(DropdownButtonFormField<String>).at(2);
      await t.ensureVisible(dropdown);
      await t.tap(dropdown);
      await t.pumpAndSettle();
      expect(find.text(p.build.label), findsNothing);
      await t.tap(find.text('0.2.0 · CORE · aaaaaaaa').last);
      await t.pumpAndSettle();
      await t.ensureVisible(find.text('Verify and provision'));
      await t.tap(find.text('Verify and provision'));
      await t.pumpAndSettle();
      expect(c.readbackSaved, isTrue);
      expect(gateway.completed, isTrue);
      expect(c.registry!.articles.single.role, 'Core');
      expect(c.registry!.devices.single.id, f.device);
    },
  );
  testWidgets('CORE cannot use an otherwise qualified LINK-only catalogue', (
    t,
  ) async {
    gateway.product = 'Core';
    await show(t);
    await t.tap(find.text('Refresh USB and firmware'));
    await t.pumpAndSettle();
    expect(find.textContaining('No qualified CORE firmware'), findsOneWidget);
    expect(
      t
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Verify and provision'),
          )
          .onPressed,
      isNull,
    );
    expect(gateway.begins, isEmpty);
  });
  testWidgets(
    'CORE firmware selection renders with its role in light appearance',
    (t) async {
      c.dispose();
      runner = CoreCatalogueRunner();
      gateway.product = 'Core';
      c = WorkshopController(
        gateway,
        f.Runner(),
        MemoryEvidence(),
        provisioner: runner,
        idFactory: () => p.requestId,
      );
      await show(t);
      await t.tap(find.text('Refresh USB and firmware'));
      await t.pumpAndSettle();
      await select(t, 1, 'Synthetic T114 · bootloader');
      await select(t, 2, '0.2.0 · CORE · aaaaaaaa');
      await t.pump();
      await expectLater(
        find.byKey(const ValueKey('provisioning-golden')),
        matchesGoldenFile('goldens/core-provisioning-light.png'),
      );
    },
    tags: 'golden',
  );
}
