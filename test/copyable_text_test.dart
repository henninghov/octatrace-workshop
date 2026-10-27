import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/ui/copyable_text.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  String? clipboard;
  bool fail = false;
  Completer<void>? pending;

  setUp(() {
    clipboard = null;
    fail = false;
    pending = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
          switch (call.method) {
            case 'Clipboard.setData':
              if (fail) throw PlatformException(code: 'unavailable');
              clipboard = (call.arguments as Map)['text'] as String;
              await pending?.future;
              return null;
            case 'Clipboard.getData':
              return {'text': clipboard};
            case 'Clipboard.hasStrings':
              return {'value': clipboard != null};
            default:
              return null;
          }
        });
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  Future<void> show(WidgetTester t, {String value = 'D000000000001'}) async {
    await t.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: CopyableText(label: 'Serial', value: value),
          ),
        ),
      ),
    );
    await t.pumpAndSettle();
  }

  testWidgets('copy icon writes the exact value without its label', (t) async {
    const text = 'Status: paired ✓\nMessage received: æøå';
    await show(t, value: text);
    await t.tap(find.byTooltip('Copy Serial'));
    await t.pumpAndSettle();
    expect(clipboard, text);
    expect(find.text('Serial copied'), findsOneWidget);
  });

  testWidgets('selectable text supports keyboard selection and copying', (
    t,
  ) async {
    await show(t);
    await t.tap(find.byType(SelectableText));
    await t.pumpAndSettle();
    await t.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
    await t.sendKeyEvent(LogicalKeyboardKey.keyA);
    await t.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
    await t.pumpAndSettle();
    expect(
      t.widget<EditableText>(find.byType(EditableText)).controller.selection,
      const TextSelection(baseOffset: 0, extentOffset: 13),
    );
    await t.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
    await t.sendKeyEvent(LogicalKeyboardKey.keyC);
    await t.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
    await t.pumpAndSettle();
    expect(clipboard, 'D000000000001');
    expect(find.text('Serial copied'), findsNothing);
    await t.sendKeyEvent(LogicalKeyboardKey.arrowLeft);
    await t.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
    for (var i = 0; i < 3; i++) {
      await t.sendKeyEvent(LogicalKeyboardKey.arrowRight);
    }
    await t.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
    await t.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
    await t.sendKeyEvent(LogicalKeyboardKey.keyC);
    await t.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
    await t.pumpAndSettle();
    expect(clipboard, 'D00');
  }, variant: TargetPlatformVariant.only(TargetPlatform.macOS));

  testWidgets('clipboard failure keeps selection and offers manual recovery', (
    t,
  ) async {
    fail = true;
    await show(t);
    await t.tap(find.byTooltip('Copy Serial'));
    await t.pumpAndSettle();
    expect(clipboard, isNull);
    expect(
      find.text('Could not copy. Select the text and copy it manually.'),
      findsOneWidget,
    );
    expect(find.byType(SelectableText), findsOneWidget);
    expect(find.text('Serial copied'), findsNothing);
  });

  testWidgets('late clipboard completion does not use a disposed screen', (
    t,
  ) async {
    pending = Completer<void>();
    await show(t);
    await t.tap(find.byTooltip('Copy Serial'));
    await t.pump();
    await t.pumpWidget(const SizedBox());
    pending!.complete();
    await t.pumpAndSettle();
    expect(clipboard, 'D000000000001');
    expect(t.takeException(), isNull);
  });

  testWidgets('long values wrap while copy stays available', (t) async {
    t.view.physicalSize = const Size(320, 600);
    t.view.devicePixelRatio = 1;
    addTearDown(t.view.resetPhysicalSize);
    addTearDown(t.view.resetDevicePixelRatio);
    final text = 'Connection paused. Reconnect when ready. ' * 12;
    await show(t, value: text);
    await t.tap(find.byTooltip('Copy Serial'));
    await t.pumpAndSettle();
    expect(clipboard, text);
    expect(t.takeException(), isNull);
  });
}
