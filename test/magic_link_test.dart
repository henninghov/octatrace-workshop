import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'ui_flow_test.dart' show MemoryEvidence;
import 'widget_test.dart' as fixtures;

class LinkGateway extends fixtures.Gateway {
  int requested = 0, exchanged = 0;
  bool failRequest = false, failExchange = false, wrongEmail = false;
  Completer<void>? requestWait;
  @override
  String? get accountEmail =>
      wrongEmail ? 'different@example.invalid' : super.accountEmail;
  @override
  Future<void> requestLink(String email) async {
    requested++;
    if (requestWait != null) await requestWait!.future;
    if (failRequest) throw StateError('synthetic mail provider failure');
    await super.requestLink(email);
  }

  @override
  Future<void> exchangeLink(String code) async {
    exchanged++;
    if (failExchange) throw StateError('synthetic expired code');
    await super.exchangeLink(code);
  }
}

Uri callback([String code = 'synthetic']) =>
    Uri.parse('$workshopCallback?code=$code');
void main() {
  late LinkGateway g;
  late WorkshopController c;
  setUp(() {
    g = LinkGateway();
    c = WorkshopController(g, fixtures.Runner(), MemoryEvidence());
  });
  tearDown(() => c.dispose());
  test('email validation and delivery failure retain closed access', () async {
    await c.requestLink('invalid');
    expect(g.requested, 0);
    expect(c.message, contains('account email'));
    g.failRequest = true;
    await c.requestLink(fixtures.email);
    expect(c.access, Access.signedOut);
    expect(c.registry, isNull);
    expect(c.message, contains('Could not send'));
  });
  test(
    'only verified link for the requested identity admits an operator',
    () async {
      await c.requestLink('  OPERATOR@example.invalid  ');
      expect(c.access, Access.awaitingLink);
      expect(g.exchanged, 0);
      expect(c.registry, isNull);
      await c.acceptLink(callback());
      expect(c.access, Access.ready);
      expect(g.exchanged, 1);
      await c.acceptLink(callback());
      c.linkDeliveryFailed();
      expect(g.exchanged, 1);
      expect(c.access, Access.ready);
    },
  );
  test(
    'wrong route, duplicated codes, error and cold callback cannot sign in',
    () async {
      await c.acceptLink(callback());
      expect(c.access, Access.signedOut);
      expect(g.exchanged, 0);
      await c.requestLink(fixtures.email);
      for (final uri in [
        'com.octatrace.app://login-callback?code=x',
        'com.octatrace.workshop://user@login-callback?code=x',
        'com.octatrace.workshop://login-callback:99?code=x',
        'com.octatrace.workshop://login-callback/other?code=x',
        '$workshopCallback?code=x&code=y',
        '$workshopCallback?error=access_denied',
        '$workshopCallback?code=',
        '$workshopCallback?code=x#access_token=forged',
      ]) {
        await c.acceptLink(Uri.parse(uri));
        expect(c.registry, isNull);
      }
      expect(g.exchanged, 0);
      await c.acceptLink(callback());
      expect(c.access, Access.ready);
    },
  );
  test(
    'mismatched server email and expired codes keep the registry closed',
    () async {
      await c.requestLink(fixtures.email);
      g.wrongEmail = true;
      await c.acceptLink(callback());
      expect(c.access, Access.signedOut);
      expect(g.account, isNull);
      g.wrongEmail = false;
      g.failExchange = true;
      await c.requestLink(fixtures.email);
      await c.acceptLink(callback());
      expect(c.message, contains('expired'));
      expect(c.registry, isNull);
    },
  );
  test('cancelled request cannot admit a late link', () async {
    await c.requestLink(fixtures.email);
    await c.signOut();
    await c.acceptLink(callback());
    expect(g.exchanged, 0);
    expect(c.registry, isNull);
  });
  test(
    'callback arriving before mail request response is verified once',
    () async {
      g.requestWait = Completer<void>();
      final sending = c.requestLink(fixtures.email);
      await c.requestLink(fixtures.email);
      expect(g.requested, 1);
      await c.acceptLink(callback());
      expect(g.exchanged, 0);
      g.requestWait!.complete();
      await sending;
      await Future<void>.delayed(Duration.zero);
      expect(g.exchanged, 1);
      expect(c.access, Access.ready);
    },
  );
  test(
    'logout during delivery discards a queued callback and late response',
    () async {
      g.requestWait = Completer<void>();
      final sending = c.requestLink(fixtures.email);
      await c.acceptLink(callback());
      final closing = c.signOut();
      g.requestWait!.complete();
      await sending;
      await closing;
      expect(g.exchanged, 0);
      expect(c.access, Access.signedOut);
      expect(g.account, isNull);
    },
  );
  testWidgets(
    'mail delivery and verified sign-in display their pending states',
    (t) async {
      g.requestWait = Completer<void>();
      await t.pumpWidget(WorkshopApp(controller: c));
      await t.pumpAndSettle();
      await t.enterText(find.byType(TextField), fixtures.email);
      await t.tap(find.text('Send sign-in link'));
      await t.pump();
      expect(find.text('Sending link…'), findsOneWidget);
      expect(t.widget<TextField>(find.byType(TextField)).enabled, isFalse);
      g.requestWait!.complete();
      await t.pumpAndSettle();
      g.delayed = Completer<Registry>();
      final verifying = c.acceptLink(callback());
      await t.pump();
      expect(find.text('Signing in…'), findsOneWidget);
      expect(c.registry, isNull);
      g.delayed!.complete(fixtures.data());
      await verifying;
      await t.pumpAndSettle();
      expect(c.access, Access.ready);
    },
  );
  testWidgets(
    'platform URL stream completes waiting login and errors stay closed',
    (t) async {
      final links = StreamController<Uri>();
      addTearDown(links.close);
      await t.pumpWidget(WorkshopApp(controller: c, links: links.stream));
      await t.pumpAndSettle();
      links.addError(StateError('synthetic link delivery failure'));
      await t.pumpAndSettle();
      expect(find.textContaining('could not open'), findsOneWidget);
      await t.enterText(find.byType(TextField), fixtures.email);
      await t.tap(find.text('Send sign-in link'));
      await t.pumpAndSettle();
      links.add(callback());
      await t.pumpAndSettle();
      expect(find.text('Every device starts here.'), findsOneWidget);
    },
  );
}
