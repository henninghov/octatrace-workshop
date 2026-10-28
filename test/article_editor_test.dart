import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/ui/article_editor.dart';

Future<void> openEditor(WidgetTester t) async {
  await t.pumpWidget(
    MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: TextButton(
            onPressed: () => showDialog<ArticleDraft>(
              context: context,
              builder: (_) => const ArticleEditor(),
            ),
            child: const Text('Open editor'),
          ),
        ),
      ),
    ),
  );
  await t.tap(find.text('Open editor'));
  await t.pumpAndSettle();
}

Future<void> tapVisible(WidgetTester t, Finder f) async {
  await t.ensureVisible(f);
  await t.tap(f);
  await t.pumpAndSettle();
}

void main() {
  testWidgets(
    'separate part inputs save description text without hidden separators',
    (t) async {
      ArticleDraft? saved;
      await t.pumpWidget(
        MaterialApp(
          home: Builder(
            builder: (context) => Scaffold(
              body: TextButton(
                onPressed: () async {
                  saved = await showDialog<ArticleDraft>(
                    context: context,
                    builder: (_) => const ArticleEditor(),
                  );
                },
                child: const Text('Open editor'),
              ),
            ),
          ),
        ),
      );
      await t.tap(find.text('Open editor'));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('article-code')), 'SYNTHETIC-01');
      await t.enterText(
        find.byKey(const Key('article-name')),
        'Synthetic assembly',
      );
      await t.enterText(find.byKey(const Key('article-case')), 'Case A');
      await t.enterText(
        find.byKey(const Key('part-0-number')),
        '  TEST-BOARD  ',
      );
      await t.enterText(
        find.byKey(const Key('part-0-description')),
        'Synthetic radio board | GPS',
      );
      await t.enterText(find.byKey(const Key('part-0-quantity')), '1');
      for (final row in [1, 2]) {
        await tapVisible(t, find.text('Create part'));
        await t.enterText(
          find.byKey(Key('part-$row-number')),
          'TEST-PART-$row',
        );
        await t.enterText(
          find.byKey(Key('part-$row-description')),
          'Synthetic component $row',
        );
        await t.enterText(find.byKey(Key('part-$row-quantity')), '${row + 1}');
      }
      await t.ensureVisible(find.text('Save revision'));
      await t.tap(find.text('Save revision'));
      await t.pumpAndSettle();
      expect(saved, isNotNull);
      expect(saved!.parts, [
        {
          'part_number': 'TEST-BOARD',
          'description': 'Synthetic radio board | GPS',
          'quantity': 1,
        },
        for (final row in [1, 2])
          {
            'part_number': 'TEST-PART-$row',
            'description': 'Synthetic component $row',
            'quantity': row + 1,
          },
      ]);
    },
  );
  testWidgets(
    'inline errors keep entered values and reject invalid quantities',
    (t) async {
      await openEditor(t);
      await t.enterText(find.byKey(const Key('article-code')), 'SYNTHETIC-01');
      await t.enterText(
        find.byKey(const Key('article-name')),
        'Synthetic assembly',
      );
      await t.enterText(find.byKey(const Key('article-case')), 'Case A');
      await tapVisible(t, find.text('Save revision'));
      expect(find.text('Enter a part number.'), findsOneWidget);
      expect(find.text('Enter a description.'), findsOneWidget);
      expect(
        t
            .widget<TextFormField>(find.byKey(const Key('article-code')))
            .controller!
            .text,
        'SYNTHETIC-01',
      );
      await t.enterText(find.byKey(const Key('part-0-number')), 'TEST-BOARD');
      await t.enterText(
        find.byKey(const Key('part-0-description')),
        'Synthetic board',
      );
      for (final invalid in [
        '',
        '0',
        '-1',
        '1.5',
        '1000001',
        '999999999999999999999999999999999',
      ]) {
        await t.enterText(find.byKey(const Key('part-0-quantity')), invalid);
        await tapVisible(t, find.text('Save revision'));
        expect(
          find.text('Use a whole number from 1 to 1000000.'),
          findsOneWidget,
        );
      }
      await t.enterText(find.byKey(const Key('part-0-quantity')), '1000000');
      await tapVisible(t, find.text('Save revision'));
      expect(find.byType(ArticleEditor), findsNothing);
    },
  );
  testWidgets('database length limits are shown at the matching inputs', (
    t,
  ) async {
    await openEditor(t);
    for (final entry in {
      'article-code': 81,
      'article-name': 161,
      'article-case': 101,
      'part-0-number': 101,
      'part-0-description': 241,
    }.entries) {
      await t.enterText(find.byKey(Key(entry.key)), 'x' * entry.value);
    }
    await tapVisible(t, find.text('Save revision'));
    expect(find.text('Use 80 characters or fewer.'), findsOneWidget);
    expect(find.text('Use 160 characters or fewer.'), findsOneWidget);
    expect(find.text('Use 100 characters or fewer.'), findsNWidgets(2));
    expect(find.text('Use 240 characters or fewer.'), findsOneWidget);
  });
  testWidgets(
    'adding and removing parts preserves neighbouring values and detects duplicate codes',
    (t) async {
      await openEditor(t);
      expect(
        t
            .widget<IconButton>(
              find.byWidgetPredicate(
                (w) => w is IconButton && w.tooltip == 'Remove part 1',
              ),
            )
            .onPressed,
        isNull,
      );
      await t.enterText(find.byKey(const Key('part-0-number')), 'TEST-SAME');
      await tapVisible(t, find.text('Create part'));
      await t.enterText(find.byKey(const Key('part-1-number')), 'TEST-SAME');
      await t.enterText(
        find.byKey(const Key('part-1-description')),
        'Keep this description',
      );
      await t.enterText(find.byKey(const Key('part-1-quantity')), '3');
      await tapVisible(t, find.text('Save revision'));
      expect(find.textContaining('Already listed'), findsNWidgets(2));
      await tapVisible(t, find.byTooltip('Remove part 1'));
      expect(find.byKey(const Key('part-0-number')), findsNothing);
      expect(
        t
            .widget<TextFormField>(find.byKey(const Key('part-1-description')))
            .controller!
            .text,
        'Keep this description',
      );
      expect(
        t
            .widget<TextFormField>(find.byKey(const Key('part-1-quantity')))
            .controller!
            .text,
        '3',
      );
      expect(find.textContaining('Already listed'), findsNothing);
      await tapVisible(t, find.text('Cancel'));
      expect(t.takeException(), isNull);
    },
  );
  testWidgets(
    'part inputs stack within a narrow dialog without horizontal overflow',
    (t) async {
      t.view.physicalSize = const Size(640, 800);
      t.view.devicePixelRatio = 1;
      addTearDown(t.view.resetPhysicalSize);
      addTearDown(t.view.resetDevicePixelRatio);
      await openEditor(t);
      expect(find.text('Description'), findsOneWidget);
      expect(t.takeException(), isNull);
      await tapVisible(t, find.text('Cancel'));
    },
  );
}
