import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'widget_test.dart' as fixtures;

class MemoryEvidence implements EvidenceStore {
  final values = <Json>[];
  @override
  Future<String> reservation(
    String account,
    String parameters,
    String Function() createId,
  ) async => createId();
  @override
  Future<void> acknowledgeReservation(
    String account,
    String parameters,
    String expectedId,
  ) async {}
  @override
  Future<void> save(String account, Json record) async {
    values.add(record);
  }

  @override
  Future<List<Json>> pending(String account) async => List.of(values);
  @override
  Future<void> synced(String account, String id) async {
    values.removeWhere((r) => r['id'] == id);
  }
}

class HistoryGateway extends fixtures.Gateway {
  bool empty = false;
  @override
  Future<Registry> load() async => Registry.fromJson({
    'articles': empty
        ? []
        : [
            {
              'id': fixtures.revision,
              'article_id': 'article',
              'code': 'LINK-TEST',
              'name': 'LINK',
              'role': 'Link',
              'revision': 1,
              'case_version': 'A',
              'parts': [],
            },
          ],
    'devices': [],
    'runs': [
      {
        'event_type': 'diagnostic',
        'recorded_at': '2026-10-26T12:00:00Z',
        'device_id': fixtures.device,
        'report': {'ok': false},
      },
    ],
  });
}

class WaitingRunner extends fixtures.Runner {
  final waiting = Completer<Json>();
  @override
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  }) => waiting.future;
  @override
  Future<void> cancel() async {
    cancelled = true;
    if (!waiting.isCompleted) waiting.complete({'cancelled': true});
  }
}

class MixedDevices extends fixtures.Gateway {
  @override
  Future<Registry> load() async => Registry.fromJson({
    'articles': [
      for (final role in ['Link', 'Core'])
        {
          'id': role,
          'article_id': role,
          'code': '$role-TEST',
          'name': role,
          'role': role,
          'revision': 2,
          'case_version': 'A',
          'parts': [],
        },
    ],
    'devices': [
      for (var i = 0; i < 3; i++)
        {
          'id': '30000000-0000-4000-8000-00000000000${i + 1}',
          'serial': 'D00000000000${i + 1}',
          'article_revision_id': ['Link', 'Core', 'missing'][i],
          'provisioning_state': i == 1 ? 'provisioned' : 'reserved',
          'owner_user_id': i == 1 ? fixtures.actor : null,
          'firmware_version': null,
        },
    ],
    'runs': [],
  });
}

void main() {
  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final regular = FontLoader('Excon')
      ..addFont(rootBundle.load('assets/fonts/Excon-Regular.otf'));
    regular.addFont(rootBundle.load('assets/fonts/Excon-Medium.otf'));
    await regular.load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  late fixtures.Gateway gateway;
  late WorkshopController controller;
  setUp(() {
    gateway = fixtures.Gateway();
    controller = WorkshopController(
      gateway,
      fixtures.Runner(),
      MemoryEvidence(),
    );
  });
  tearDown(() => controller.dispose());
  Future<void> show(WidgetTester tester, {bool signedIn = true}) async {
    tester.view.physicalSize = const Size(1100, 850);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    if (signedIn) {
      await fixtures.signIn(controller);
    }
    await tester.pumpWidget(
      RepaintBoundary(
        key: const Key('capture'),
        child: WorkshopApp(controller: controller),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('magic link keeps operator access closed until verified', (
    t,
  ) async {
    gateway.denied = true;
    await show(t, signedIn: false);
    await t.enterText(find.byType(TextField).at(0), 'operator@example.invalid');
    await t.tap(find.text('Send sign-in link'));
    await t.pumpAndSettle();
    expect(controller.access, Access.awaitingLink);
    expect(controller.registry, isNull);
    expect(find.text('Password'), findsNothing);
    await controller.acceptLink(Uri.parse('$workshopCallback?code=synthetic'));
    await t.pumpAndSettle();
    expect(
      find.textContaining('does not have Workshop operator access'),
      findsOneWidget,
    );
  });
  testWidgets('article creation validates input and saves a typed parts list', (
    t,
  ) async {
    await show(t);
    await t.tap(find.text('Articles'));
    await t.pumpAndSettle();
    await t.tap(find.text('New article'));
    await t.pumpAndSettle();
    await t.tap(find.text('Save revision'));
    await t.pumpAndSettle();
    expect(find.text('Enter an article code.'), findsOneWidget);
    final fields = find.byType(TextField);
    await t.enterText(fields.at(0), 'CORE-TEST');
    await t.enterText(fields.at(1), 'Synthetic CORE');
    await t.enterText(fields.at(2), 'Case B');
    await t.enterText(find.byKey(const Key('part-0-number')), 'PCB-B');
    await t.enterText(find.byKey(const Key('part-0-description')), 'Board B');
    await t.tap(find.byType(DropdownButtonFormField<String>));
    await t.pumpAndSettle();
    await t.tap(find.text('CORE').last);
    await t.pumpAndSettle();
    await t.tap(find.text('Save revision'));
    await t.pumpAndSettle();
    expect(gateway.articlesCreated, 1);
  });
  testWidgets(
    'new article revision starts from original parts and can be cancelled',
    (t) async {
      await show(t);
      await t.tap(find.text('Articles'));
      await t.pumpAndSettle();
      await t.tap(find.text('New revision'));
      await t.pumpAndSettle();
      expect(
        t
            .widget<TextFormField>(find.byKey(const Key('part-0-number')))
            .controller!
            .text,
        'PCB-A',
      );
      await t.tap(find.text('Cancel'));
      await t.pumpAndSettle();
      expect(gateway.revisionsCreated, 0);
      await t.tap(find.text('New revision'));
      await t.pumpAndSettle();
      await t.enterText(find.byType(TextField).first, 'Case B');
      await t.tap(find.text('Save revision'));
      await t.pumpAndSettle();
      expect(gateway.revisionsCreated, 1);
    },
  );
  testWidgets(
    'provisioning uses article revision without a separate hardware field',
    (t) async {
      await show(t);
      await t.tap(find.text('Provisioning'));
      await t.pumpAndSettle();
      expect(find.text('Article and revision'), findsOneWidget);
      expect(find.text('Hardware revision'), findsNothing);
      expect(find.byType(TextField), findsNothing);
    },
  );
  testWidgets('device registry shows type and copyable identity fields', (
    t,
  ) async {
    await show(t);
    expect(find.text('LINK'), findsOneWidget);
    expect(find.text('Serial'), findsOneWidget);
    expect(find.text('UUID'), findsOneWidget);
    expect(find.text('Status'), findsOneWidget);
    expect(find.byTooltip('Copy Serial'), findsOneWidget);
    expect(find.byTooltip('Copy UUID'), findsOneWidget);
    expect(find.byTooltip('Copy Status'), findsOneWidget);
    expect(find.text('reserved · Unclaimed'), findsOneWidget);
  });
  testWidgets(
    'device list stacks identity fields in a narrower desktop window',
    (t) async {
      await show(t);
      t.view.physicalSize = const Size(850, 850);
      await t.pumpAndSettle();
      expect(
        t.getTopLeft(find.text('UUID')).dy,
        greaterThan(t.getBottomLeft(find.text('Serial')).dy),
      );
      expect(t.takeException(), isNull);
    },
  );
  testWidgets(
    'registry copies exact fields without opening or changing a device',
    (t) async {
      String? copied;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') {
              copied = (call.arguments as Map)['text'] as String;
            }
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(SystemChannels.platform, null),
      );
      await show(t);
      for (final entry in {
        'Serial': 'D000000000001',
        'UUID': fixtures.device,
        'Status': 'reserved · Unclaimed',
      }.entries) {
        await t.tap(find.byTooltip('Copy ${entry.key}'));
        await t.pumpAndSettle();
        expect(copied, entry.value);
        expect(find.text('Workspace / Devices'), findsOneWidget);
      }
      final waiting = Completer<void>();
      final action = controller.action(() => waiting.future);
      await t.pump();
      expect(
        t
            .widget<IconButton>(
              find.byWidgetPredicate(
                (w) => w is IconButton && w.tooltip == 'Open device',
              ),
            )
            .onPressed,
        isNull,
      );
      await t.tap(find.byTooltip('Copy UUID'));
      await t.pump();
      expect(copied, fixtures.device);
      waiting.complete();
      await action;
      await t.pumpAndSettle();
      expect(gateway.requests, isEmpty);
      expect(gateway.diagnostics, 0);
    },
  );
  testWidgets(
    'registry keeps LINK CORE and missing-metadata records across statuses',
    (t) async {
      controller.dispose();
      controller = WorkshopController(
        MixedDevices(),
        fixtures.Runner(),
        MemoryEvidence(),
      );
      await show(t);
      expect(find.text('LINK'), findsOneWidget);
      expect(find.text('CORE'), findsOneWidget);
      expect(find.text('Unknown device type'), findsOneWidget);
      expect(find.text('reserved · Unclaimed'), findsNWidgets(2));
      expect(find.text('provisioned · Claimed'), findsOneWidget);
      expect(find.byTooltip('Copy Serial'), findsNWidgets(3));
      await t.tap(find.text('LINK'));
      await t.pumpAndSettle();
      expect(find.text('Workspace / Provisioning'), findsOneWidget);
      await t.tap(find.text('Devices'));
      await t.pumpAndSettle();
      await t.ensureVisible(find.byTooltip('Open device').last);
      await t.tap(find.byTooltip('Open device').last);
      await t.pumpAndSettle();
      expect(find.textContaining('Unknown device type'), findsOneWidget);
    },
  );
  testWidgets(
    'status errors and device details offer selectable exact-message copying',
    (t) async {
      String? copied;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') {
              copied = (call.arguments as Map)['text'] as String;
            }
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(SystemChannels.platform, null),
      );
      await show(t);
      await controller.action(
        () async => throw StateError('synthetic failure'),
      );
      await t.pumpAndSettle();
      await t.tap(find.byTooltip('Copy Message'));
      await t.pumpAndSettle();
      expect(copied, controller.message);
      await t.tap(find.byTooltip('Open device'));
      await t.pumpAndSettle();
      await t.tap(find.byTooltip('Copy Serial'));
      await t.pumpAndSettle();
      expect(copied, 'D000000000001');
      await t.tap(find.byTooltip('Copy UUID'));
      await t.pumpAndSettle();
      expect(copied, fixtures.device);
      await t.tap(find.byTooltip('Copy Status'));
      await t.pumpAndSettle();
      expect(copied, 'reserved · Unclaimed');
      await t.ensureVisible(find.text('Read identity with shared runner'));
      await t.ensureVisible(find.text('Read identity with shared runner'));
      await t.tap(find.text('Read identity with shared runner'));
      await t.pumpAndSettle();
      await t.ensureVisible(find.byTooltip('Copy Diagnostic'));
      await t.tap(find.byTooltip('Copy Diagnostic'));
      await t.pumpAndSettle();
      expect(copied, contains('"provisioned": false'));
      expect(controller.registry!.devices.single.state, 'reserved');
    },
  );
  testWidgets(
    'reservation selects the complete article revision and production class',
    (t) async {
      await show(t);
      await t.tap(find.text('New device'));
      await t.pumpAndSettle();
      await t.tap(find.byType(DropdownButtonFormField<String>).first);
      await t.pumpAndSettle();
      await t.tap(find.textContaining('LINK-TEST').last);
      await t.pumpAndSettle();
      await t.tap(find.byType(DropdownButtonFormField<String>).last);
      await t.pumpAndSettle();
      await t.tap(find.text('O — Production').last);
      await t.pumpAndSettle();
      await t.tap(find.text('Reserve device identity'));
      await t.pumpAndSettle();
      expect(gateway.requests.length, 1);
    },
  );
  testWidgets(
    'shared runner diagnostics stay separate from provisioning completion',
    (t) async {
      await show(t);
      await t.tap(find.byTooltip('Open device'));
      await t.pumpAndSettle();
      await t.enterText(
        find.byType(TextField).first,
        '/dev/cu.usbmodemSynthetic',
      );
      await t.enterText(find.byType(TextField).last, 'a' * 64);
      await t.ensureVisible(find.text('Read identity with shared runner'));
      await t.tap(find.text('Read identity with shared runner'));
      await t.pumpAndSettle();
      expect(
        find.text('Diagnostic saved · provisioning unchanged'),
        findsOneWidget,
      );
      await t.ensureVisible(find.text('Run shared USB checks'));
      await t.tap(find.text('Run shared USB checks'));
      await t.pumpAndSettle();
      expect(gateway.diagnostics, 2);
      await t.tap(find.text('Setup history'));
      await t.pumpAndSettle();
      expect(find.text('No preparation records yet.'), findsOneWidget);
      await t.tap(find.byTooltip('Refresh registry'));
      await t.pumpAndSettle();
      await t.tap(find.text('Sign out'));
      await t.pumpAndSettle();
      expect(find.text('Send sign-in link'), findsOneWidget);
      expect(controller.registry, isNull);
    },
  );
  testWidgets(
    'pending diagnostic upload is visible and retries the same local record',
    (t) async {
      await show(t);
      gateway.failSave = true;
      await t.tap(find.byTooltip('Open device'));
      await t.pumpAndSettle();
      await t.ensureVisible(find.text('Read identity with shared runner'));
      await t.tap(find.text('Read identity with shared runner'));
      await t.pumpAndSettle();
      expect(find.textContaining('could not be completed'), findsOneWidget);
      expect(find.text('Readback received · record not saved'), findsOneWidget);
      await t.tap(find.text('Setup history'));
      await t.pumpAndSettle();
      expect(find.textContaining('1 local evidence records'), findsOneWidget);
      gateway.failSave = false;
      await t.tap(find.text('Retry evidence upload'));
      await t.pumpAndSettle();
      expect(gateway.diagnostics, 1);
      expect(find.text('Retry evidence upload'), findsNothing);
    },
  );
  testWidgets(
    'history expands its evidence and empty article/device states give direction',
    (t) async {
      controller.dispose();
      final history = HistoryGateway();
      controller = WorkshopController(
        history,
        fixtures.Runner(),
        MemoryEvidence(),
      );
      await show(t);
      expect(find.textContaining('No devices registered'), findsOneWidget);
      await t.tap(find.text('Articles'));
      await t.pumpAndSettle();
      history.empty = true;
      await t.tap(find.byTooltip('Refresh registry'));
      await t.pumpAndSettle();
      expect(find.textContaining('Create the first article'), findsOneWidget);
      await t.tap(find.text('Setup history'));
      await t.pumpAndSettle();
      await t.tap(find.textContaining('diagnostic ·'));
      await t.pumpAndSettle();
      expect(find.textContaining('"ok": false'), findsOneWidget);
    },
  );
  testWidgets(
    'busy diagnostics disable device navigation and Cancel releases the screen',
    (t) async {
      controller.dispose();
      final runner = WaitingRunner();
      controller = WorkshopController(gateway, runner, MemoryEvidence());
      await show(t);
      await t.tap(find.byTooltip('Open device'));
      await t.pumpAndSettle();
      await t.ensureVisible(find.text('Read identity with shared runner'));
      await t.tap(find.text('Read identity with shared runner'));
      await t.pump();
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
      expect(
        t
            .widget<TextButton>(find.widgetWithText(TextButton, 'Articles'))
            .onPressed,
        isNull,
      );
      await t.ensureVisible(find.text('Cancel'));
      await t.tap(find.text('Cancel'));
      await t.pumpAndSettle();
      expect(runner.cancelled, isTrue);
      expect(controller.busy, isFalse);
    },
  );
  testWidgets(
    'keyboard submission requests a link and cancellation closes admission',
    (t) async {
      await show(t, signedIn: false);
      await t.enterText(find.byType(TextField), 'operator@example.invalid');
      await t.testTextInput.receiveAction(TextInputAction.done);
      await t.pumpAndSettle();
      expect(controller.access, Access.awaitingLink);
      expect(find.text('Send a new link'), findsOneWidget);
      await t.tap(find.text('Cancel sign-in'));
      await t.pumpAndSettle();
      expect(controller.access, Access.signedOut);
      expect(gateway.account, isNull);
    },
  );
  testWidgets('article editor shows structured part rows in dark appearance', (
    t,
  ) async {
    await show(t);
    await t.tap(find.text('Dark mode'));
    await t.pumpAndSettle();
    await t.tap(find.text('Articles'));
    await t.pumpAndSettle();
    await t.tap(find.text('New article'));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('article-code')), 'SYNTHETIC-01');
    await t.enterText(
      find.byKey(const Key('article-name')),
      'Synthetic LINK assembly',
    );
    await t.enterText(find.byKey(const Key('article-case')), 'Case A');
    await t.enterText(find.byKey(const Key('part-0-number')), 'TEST-BOARD');
    await t.enterText(
      find.byKey(const Key('part-0-description')),
      'Synthetic radio board',
    );
    await t.ensureVisible(find.text('Create part'));
    await t.tap(find.text('Create part'));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('part-1-number')), 'TEST-CASE');
    await t.enterText(
      find.byKey(const Key('part-1-description')),
      'Synthetic enclosure',
    );
    await t.pumpAndSettle();
    await t.pump();
    await expectLater(
      find.byKey(const Key('capture')),
      matchesGoldenFile('goldens/article-editor-dark.png'),
    );
  }, tags: 'golden');
  testWidgets(
    'device registry has readable type and copy controls in light appearance',
    (t) async {
      await show(t);
      await t.pump();
      await expectLater(
        find.byKey(const Key('capture')),
        matchesGoldenFile('goldens/devices-light.png'),
      );
    },
    tags: 'golden',
  );
  testWidgets(
    'device registry has readable type and copy controls in dark appearance',
    (t) async {
      await show(t);
      await t.tap(find.text('Dark mode'));
      await t.pumpAndSettle();
      await t.pump();
      await expectLater(
        find.byKey(const Key('capture')),
        matchesGoldenFile('goldens/devices-dark.png'),
      );
    },
    tags: 'golden',
  );
  testWidgets('login design uses original compass and wordmark', (t) async {
    await show(t, signedIn: false);
    await t.pump();
    await expectLater(
      find.byKey(const Key('capture')),
      matchesGoldenFile('goldens/login-light.png'),
    );
  }, tags: 'golden');
  testWidgets('articles design retains revision and component information', (
    t,
  ) async {
    await show(t);
    await t.tap(find.text('Articles'));
    await t.pumpAndSettle();
    await t.pump();
    await expectLater(
      find.byKey(const Key('capture')),
      matchesGoldenFile('goldens/articles-light.png'),
    );
  }, tags: 'golden');
  for (final appearance in ['light', 'dark']) {
    testWidgets(
      'new device entry keeps creation separate in $appearance appearance',
      (t) async {
        await show(t);
        if (appearance == 'dark') {
          await t.tap(find.text('Dark mode'));
          await t.pumpAndSettle();
        }
        await t.tap(find.text('New device'));
        await t.pumpAndSettle();
        expect(find.text('Registry device'), findsNothing);
        await t.pump();
        await expectLater(
          find.byKey(const Key('capture')),
          matchesGoldenFile('goldens/new-device-$appearance.png'),
        );
      },
      tags: 'golden',
    );
  }
  testWidgets('shared part picker shows canonical identity and search', (
    t,
  ) async {
    await show(t);
    await t.tap(find.text('Articles'));
    await t.pumpAndSettle();
    await t.tap(find.text('New article'));
    await t.pumpAndSettle();
    await t.ensureVisible(find.text('Choose existing part'));
    await t.tap(find.text('Choose existing part'));
    await t.pumpAndSettle();
    await t.pump();
    await expectLater(
      find.byKey(const Key('capture')),
      matchesGoldenFile('goldens/shared-part-picker-light.png'),
    );
  }, tags: 'golden');
}
