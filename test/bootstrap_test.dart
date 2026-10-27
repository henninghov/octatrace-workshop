import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/main.dart' as entry;
import 'package:octatrace_workshop/ui/workshop_app.dart';

void main() {
  testWidgets('bootstrap shows login before any account or hardware access', (
    tester,
  ) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('com.llfbandit.app_links/events'),
          (call) async => null,
        );
    await tester.runAsync(() async => entry.main());
    await tester.pumpAndSettle();
    expect(find.text('Welcome to the bench.'), findsOneWidget);
    expect(find.text('Send sign-in link'), findsOneWidget);
    final controller = tester
        .widget<WorkshopApp>(find.byType(WorkshopApp))
        .controller;
    // SDK worker-isolate teardown must run in the real async zone, rather
    // than wait on fake-clock microtasks from inside runAsync.
    if (controller != null) {
      await tester.runAsync(() async {
        controller.dispose();
        await controller.closed;
      });
    }
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump();
  });
}
