import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'widget_test.dart' as f;
import 'ui_flow_test.dart' show MemoryEvidence;

class EntryGateway extends f.Gateway {
  bool noDevices = false, reserved = false;
  List<Json>? savedParts;
  String? savedRole;
  @override
  Future<Registry> load() async => Registry.fromJson({
    'articles': [
      for (final role in ['Link', 'Core'])
        {
          'id': role,
          'article_id': role,
          'code': '$role-TEST',
          'name': 'Synthetic $role',
          'role': role,
          'revision': 1,
          'case_version': 'A',
          'parts': [
            {
              'part_number': 'PCB-A',
              'description': 'Shared board A',
              'quantity': role == 'Link' ? 1 : 3,
            },
            {
              'part_number': 'CASE-$role',
              'description': '$role enclosure',
              'quantity': 1,
            },
          ],
        },
    ],
    'devices': [
      if (!noDevices)
        {
          'id': f.device,
          'serial': 'D000000000001',
          'article_revision_id': 'Link',
          'provisioning_state': 'provisioned',
          'owner_user_id': null,
        },
      if (reserved)
        {
          'id': '30000000-0000-4000-8000-000000000002',
          'serial': 'D000000000002',
          'article_revision_id': 'Core',
          'provisioning_state': 'reserved',
          'owner_user_id': null,
        },
    ],
    'runs': [],
  });
  @override
  Future<String> reserve({
    required String requestId,
    required String revisionId,
    required String serialClass,
  }) async {
    await super.reserve(
      requestId: requestId,
      revisionId: revisionId,
      serialClass: serialClass,
    );
    expect(revisionId, 'Core');
    expect(serialClass, 'D');
    reserved = true;
    return '30000000-0000-4000-8000-000000000002';
  }

  @override
  Future<void> createArticle({
    required String code,
    required String name,
    required String role,
    required String caseVersion,
    required List<Json> parts,
  }) async {
    articlesCreated++;
    savedParts = parts;
    savedRole = role;
  }
}

Future<void> tapEntry(WidgetTester t, Finder finder) async {
  await t.ensureVisible(finder);
  await t.tap(finder);
  await t.pumpAndSettle();
}

void main() {
  late EntryGateway gateway;
  late WorkshopController controller;
  setUp(() {
    gateway = EntryGateway();
    controller = WorkshopController(gateway, f.Runner(), MemoryEvidence());
  });
  tearDown(() => controller.dispose());
  Future<void> show(WidgetTester t) async {
    await t.binding.setSurfaceSize(const Size(1300, 1100));
    addTearDown(() => t.binding.setSurfaceSize(null));
    await f.signIn(controller);
    await t.pumpWidget(WorkshopApp(controller: controller));
    await t.pumpAndSettle();
  }

  Future<void> chooseCore(WidgetTester t) async {
    await tapEntry(
      t,
      find.widgetWithText(
        DropdownButtonFormField<String>,
        'Article and revision',
      ),
    );
    await tapEntry(t, find.textContaining('Core-TEST').last);
  }

  Future<void> article(WidgetTester t) async {
    await tapEntry(t, find.text('Articles'));
    await tapEntry(t, find.text('New article'));
    await t.enterText(find.byKey(const Key('article-code')), 'SYNTHETIC-NEW');
    await t.enterText(
      find.byKey(const Key('article-name')),
      'Synthetic assembly',
    );
    await t.enterText(find.byKey(const Key('article-case')), 'Case A');
  }

  testWidgets(
    'new device hides existing selection and opens the newly reserved identity',
    (t) async {
      await show(t);
      await tapEntry(t, find.text('New device'));
      expect(find.text('Registry device'), findsNothing);
      expect(find.text('Article and revision'), findsOneWidget);
      expect(find.byTooltip('Copy UUID'), findsNothing);
      expect(gateway.requests, isEmpty);
      await chooseCore(t);
      await tapEntry(t, find.text('Reserve device identity'));
      expect(gateway.requests, hasLength(1));
      expect(controller.registry!.devices, hasLength(2));
      expect(find.text('D000000000002'), findsWidgets);
      expect(find.text('Registry device'), findsOneWidget);
      expect(find.text('Reserve device identity'), findsNothing);
      expect(controller.registry!.devices.first.state, 'provisioned');
      await tapEntry(t, find.text('New device'));
      expect(find.text('Registry device'), findsNothing);
      await tapEntry(t, find.text('Existing device'));
      expect(find.text('Registry device'), findsOneWidget);
      expect(find.text('Reserve device identity'), findsNothing);
      expect(gateway.requests, hasLength(1));
    },
  );

  testWidgets(
    'existing device never offers allocation and empty registry gives a new-device direction',
    (t) async {
      gateway.noDevices = true;
      await show(t);
      await tapEntry(t, find.text('Provisioning'));
      await tapEntry(t, find.text('Existing device'));
      expect(find.text('Reserve device identity'), findsNothing);
      expect(find.textContaining('No devices registered'), findsOneWidget);
      await tapEntry(t, find.text('New device'));
      expect(find.text('Article and revision'), findsOneWidget);
      expect(gateway.requests, isEmpty);
    },
  );

  testWidgets(
    'failed reservation preserves creation choices and successful retry selects the new record',
    (t) async {
      await show(t);
      await tapEntry(t, find.text('New device'));
      await chooseCore(t);
      gateway.failReserve = true;
      await tapEntry(t, find.text('Reserve device identity'));
      expect(gateway.reserved, isFalse);
      expect(find.textContaining('could not be completed'), findsOneWidget);
      expect(find.text('Registry device'), findsNothing);
      gateway.failReserve = false;
      await tapEntry(t, find.text('Reserve device identity'));
      expect(controller.registry!.devices, hasLength(2));
      expect(find.text('Registry device'), findsOneWidget);
    },
  );

  testWidgets(
    'shared part picker deduplicates across articles and saves an independent quantity',
    (t) async {
      await show(t);
      await article(t);
      await tapEntry(t, find.text('Choose existing part'));
      await t.enterText(find.byKey(const Key('part-search')), 'shared board');
      await t.pumpAndSettle();
      expect(find.text('PCB-A — Shared board A'), findsOneWidget);
      await tapEntry(t, find.text('PCB-A — Shared board A'));
      expect(
        t
            .widget<TextField>(
              find.descendant(
                of: find.byKey(const Key('part-0-number')),
                matching: find.byType(TextField),
              ),
            )
            .readOnly,
        isTrue,
      );
      expect(
        t
            .widget<TextField>(
              find.descendant(
                of: find.byKey(const Key('part-0-description')),
                matching: find.byType(TextField),
              ),
            )
            .readOnly,
        isTrue,
      );
      await t.enterText(find.byKey(const Key('part-0-quantity')), '2');
      await tapEntry(t, find.text('Save revision'));
      expect(gateway.savedParts, [
        {
          'part_number': 'PCB-A',
          'description': 'Shared board A',
          'quantity': 2,
        },
      ]);
      expect(
        controller.registry!.articles.map((a) => a.parts.first['quantity']),
        [1, 3],
      );
    },
  );

  testWidgets('part search, cancel and duplicate guidance preserve the draft', (
    t,
  ) async {
    await show(t);
    await article(t);
    await t.enterText(find.byKey(const Key('part-0-number')), 'PCB-A');
    await t.enterText(
      find.byKey(const Key('part-0-description')),
      'Wrong replacement',
    );
    await tapEntry(t, find.text('Save revision'));
    expect(
      find.text('Part already exists. Choose it from existing parts.'),
      findsOneWidget,
    );
    await tapEntry(t, find.text('Choose existing part'));
    await t.enterText(
      find.byKey(const Key('part-search')),
      'no such synthetic part',
    );
    await t.pumpAndSettle();
    expect(find.text('No matching parts.'), findsOneWidget);
    await tapEntry(t, find.text('Back to article'));
    expect(
      t
          .widget<TextFormField>(find.byKey(const Key('part-0-description')))
          .controller!
          .text,
      'Wrong replacement',
    );
    await t.enterText(find.byKey(const Key('part-0-number')), 'NEW-PART');
    await tapEntry(t, find.text('Choose existing part'));
    await tapEntry(t, find.text('PCB-A — Shared board A'));
    expect(find.byKey(const Key('part-1-number')), findsOneWidget);
    await tapEntry(t, find.text('Choose existing part'));
    expect(
      t
          .widget<ListTile>(
            find.widgetWithText(ListTile, 'PCB-A — Shared board A'),
          )
          .enabled,
      isFalse,
    );
    await tapEntry(t, find.text('Back to article'));
    await tapEntry(t, find.text('Save revision'));
    expect(gateway.savedParts, hasLength(2));
    expect(gateway.savedParts!.first['description'], 'Wrong replacement');
    expect(gateway.savedParts!.last['part_number'], 'PCB-A');
    expect(gateway.articlesCreated, 1);
  });
  testWidgets(
    'choosing a typed existing number restores its shared definition and keeps quantity',
    (t) async {
      await show(t);
      await article(t);
      await t.enterText(find.byKey(const Key('part-0-number')), 'PCB-A');
      await t.enterText(
        find.byKey(const Key('part-0-description')),
        'Draft description',
      );
      await t.enterText(find.byKey(const Key('part-0-quantity')), '4');
      await tapEntry(t, find.text('Choose existing part'));
      await tapEntry(t, find.text('PCB-A — Shared board A'));
      expect(find.byKey(const Key('part-1-number')), findsNothing);
      await tapEntry(t, find.text('Save revision'));
      expect(gateway.savedParts, [
        {
          'part_number': 'PCB-A',
          'description': 'Shared board A',
          'quantity': 4,
        },
      ]);
    },
  );
  testWidgets(
    'reservation response opens the exact record even when it was already refreshed into the registry',
    (t) async {
      gateway.reserved = true;
      await show(t);
      await tapEntry(t, find.text('New device'));
      await chooseCore(t);
      await tapEntry(t, find.text('Reserve device identity'));
      expect(controller.registry!.devices, hasLength(2));
      expect(find.text('Registry device'), findsOneWidget);
      expect(find.text('D000000000002'), findsWidgets);
      expect(find.text('Reserve device identity'), findsNothing);
    },
  );
}
