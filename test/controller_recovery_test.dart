import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'ui_flow_test.dart' show MemoryEvidence;
import 'widget_test.dart' as fixtures;

class FailingRunner extends fixtures.Runner {
  @override
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  }) async => throw BenchCancelled();
}

class Revoked extends fixtures.Gateway {
  bool revoked = false;
  @override
  Future<Registry> load() async {
    if (revoked) throw OperatorDenied();
    return fixtures.data();
  }
}

class RefreshFailure extends fixtures.Gateway {
  bool fail = false;
  @override
  Future<Registry> load() async {
    if (fail) throw StateError('synthetic outage');
    return fixtures.data();
  }
}

class SignOutWait extends fixtures.Gateway {
  final ending = Completer<void>();
  int logins = 0;
  @override
  Future<void> exchangeLink(String code) async {
    logins++;
    await super.exchangeLink(code);
  }

  @override
  Future<void> signOut() async {
    await ending.future;
    await super.signOut();
  }
}

class HeldReservation extends MemoryEvidence {
  final waiting = Completer<String>();
  @override
  Future<String> reservation(
    String account,
    String parameters,
    String Function() createId,
  ) => waiting.future;
}

class BrokenCancel extends fixtures.Runner {
  @override
  Future<void> cancel() async {
    throw StateError('synthetic cleanup failure');
  }
}

class HeldLogin extends fixtures.Gateway {
  final waiting = Completer<void>();
  int authorizations = 0;
  @override
  Future<void> exchangeLink(String code) async {
    await waiting.future;
    await super.exchangeLink(code);
  }

  @override
  Future<void> authorizeOperator() async {
    authorizations++;
  }
}

class HeldRunner extends fixtures.Runner {
  final waiting = Completer<Json>();
  @override
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  }) => waiting.future;
}

void main() {
  test('sign-out during local reservation cannot send its intent with another session', () async {
    final g = fixtures.Gateway();
    final store = HeldReservation();
    final c = WorkshopController(g, fixtures.Runner(), store);
    addTearDown(c.dispose);
    await fixtures.signIn(c);
    final reservation = c.reserve(fixtures.revision, 'D');
    await Future<void>.delayed(Duration.zero);
    await c.signOut();
    await fixtures.signIn(c);
    store.waiting.complete(fixtures.device);
    await reservation;
    expect(g.requests, isEmpty);
    expect(c.access, Access.ready);
  });
  test(
    'sign-out waits for authentication then clears its late SDK session',
    () async {
      final g = HeldLogin();
      final c = WorkshopController(g, fixtures.Runner(), MemoryEvidence());
      addTearDown(c.dispose);
      final login = fixtures.signIn(c);
      await Future<void>.delayed(Duration.zero);
      final logout = c.signOut();
      g.waiting.complete();
      await login;
      await logout;
      expect(g.account, isNull);
      expect(g.authorizations, 0);
      expect(c.access, Access.signedOut);
    },
  );
  test(
    'runner cleanup failure still clears SDK auth and releases login',
    () async {
      final g = fixtures.Gateway();
      final c = WorkshopController(g, BrokenCancel(), MemoryEvidence());
      await fixtures.signIn(c);
      await c.signOut();
      expect(g.account, isNull);
      expect(c.busy, isFalse);
      c.dispose();
      await expectLater(c.closed, throwsStateError);
    },
  );
  test(
    'late USB result stays in original account evidence after logout',
    () async {
      final g = fixtures.Gateway();
      final store = MemoryEvidence();
      final runner = HeldRunner();
      final c = WorkshopController(g, runner, store);
      addTearDown(c.dispose);
      await fixtures.signIn(c);
      final operation = c.verify(
        fixtures.data().devices.single,
        fixtures.data().articles.single,
        'port',
        'build',
      );
      await Future<void>.delayed(Duration.zero);
      await c.signOut();
      runner.waiting.complete({'ok': true});
      await operation;
      expect(store.values, hasLength(1));
      expect(g.diagnostics, 0);
      expect(c.readback, isNull);
      expect(c.registry, isNull);
    },
  );

  test(
    'revocation closes cached registry access on the next request',
    () async {
      final gateway = Revoked();
      final c = WorkshopController(
        gateway,
        fixtures.Runner(),
        MemoryEvidence(),
      );
      addTearDown(c.dispose);
      await fixtures.signIn(c);
      gateway.revoked = true;
      await c.refresh();
      expect(c.access, Access.denied);
      expect(c.registry, isNull);
      expect(c.message, contains('no longer available'));
    },
  );
  test(
    'failed refresh after reservation acknowledgement preserves retry ID',
    () async {
      final root = await Directory.systemTemp.createTemp('workshop-retry-');
      addTearDown(() => root.delete(recursive: true));
      final gateway = RefreshFailure();
      final c = WorkshopController(
        gateway,
        fixtures.Runner(),
        EvidenceJournal(root),
      );
      addTearDown(c.dispose);
      await fixtures.signIn(c);
      gateway.fail = true;
      await c.reserve(fixtures.revision, 'D');
      final first = gateway.requests.single;
      gateway.fail = false;
      await c.reserve(fixtures.revision, 'D');
      expect(gateway.requests.last, first);
    },
  );
  test(
    'cancelled runner attempt is recorded without a physical pass',
    () async {
      final store = MemoryEvidence();
      final gateway = fixtures.Gateway();
      final runner = FailingRunner();
      final c = WorkshopController(
        gateway,
        runner,
        store,
        now: () => DateTime.utc(2026, 10, 26),
      );
      addTearDown(c.dispose);
      await fixtures.signIn(c);
      await c.verify(
        fixtures.data().devices.single,
        fixtures.data().articles.single,
        'port',
        'build',
      );
      expect(c.readback!['adapter_outcome'], 'cancelled');
      expect(c.readbackSaved, isTrue);
      expect(c.message, contains('USB action cancelled'));
      expect(fixtures.data().devices.single.state, 'reserved');
      await c.cancel();
      expect(runner.cancelled, isTrue);
    },
  );
  test('new sign-in waits until previous SDK logout completes', () async {
    final gateway = SignOutWait();
    final c = WorkshopController(gateway, fixtures.Runner(), MemoryEvidence());
    addTearDown(c.dispose);
    await fixtures.signIn(c);
    final logout = c.signOut();
    await Future<void>.delayed(Duration.zero);
    await fixtures.signIn(c);
    expect(gateway.logins, 1);
    expect(c.registry, isNull);
    expect(c.busy, isTrue);
    gateway.ending.complete();
    await logout;
    expect(c.busy, isFalse);
    expect(c.access, Access.signedOut);
  });
  test('partial evidence file blocks silent upload and is retained', () async {
    final root = await Directory.systemTemp.createTemp('workshop-partial-');
    addTearDown(() => root.delete(recursive: true));
    final store = EvidenceJournal(root);
    await store.pending(fixtures.actor);
    final file = File('${root.path}/${fixtures.actor}/pending/interrupted.tmp');
    await file.parent.create();
    await file.writeAsString('{');
    await expectLater(store.pending(fixtures.actor), throwsFormatException);
    expect(await file.readAsString(), '{');
  });
}
