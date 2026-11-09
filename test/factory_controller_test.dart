import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/factory_controller.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'factory_fixtures.dart' as f;

void main() {
  test('strict frozen QR corpus is bounded, identity-bound and redacted', () {
    for (final row in List<Json>.from(f.qrVectors['valid'] as List)) {
      final fields = row['fields'] as Json;
      PrivateClaimQr decode() => PrivateClaimQr.parse(
        row['text'] as String,
        deviceId: fields['device_uuid'] as String,
        role: fields['role'] as String,
        publicKeySha256: fields['public_key_sha256'] as String,
        environment: fields['environment'] as String,
      );
      expect(decode().text, row['text']);
      expect(decode().toString(), '[Private claim QR]');
    }
    final fields = f.qrFields();
    for (final row in List<Json>.from(f.qrVectors['invalid_text'] as List)) {
      expect(
        () => PrivateClaimQr.parse(
          row['text'] as String,
          deviceId: fields['device_uuid'] as String,
          role: 'Link',
          environment: row['environment'] as String,
          publicKeySha256: fields['public_key_sha256'] as String,
        ),
        throwsA(anything),
        reason: row['name'] as String,
      );
    }
    for (final args in [
      <String, String>{
        'device': f.account,
        'role': 'Link',
        'hash': fields['public_key_sha256'] as String,
      },
      {
        'device': f.unit().id,
        'role': 'Core',
        'hash': fields['public_key_sha256'] as String,
      },
      {
        'device': f.unit().id,
        'role': 'Other',
        'hash': fields['public_key_sha256'] as String,
      },
      {'device': f.unit().id, 'role': 'Link', 'hash': '00' * 32},
    ]) {
      expect(
        () => PrivateClaimQr.parse(
          f.qrRow()['text'] as String,
          deviceId: args['device']!,
          role: args['role']!,
          publicKeySha256: args['hash']!,
        ),
        throwsFormatException,
      );
    }
    expect(factoryUuid(null), isFalse);
    expect(const FactoryFailure().toString(), 'Factory operation unavailable');
  });
  test('nonsecret status validates device, role, environment and issued credential digest', () {
    for (final state in ['not_enrolled', 'pending', 'ready']) {
      expect(
        FactoryStatus.fromJson(
          f.status(state),
          deviceId: f.unit().id,
          role: 'Link',
        ).state,
        state,
      );
    }
    for (final change in [
      {'v': 2},
      {'device_id': f.account},
      {'state': 'unknown'},
      {'role': 'Core'},
      {'environment': 'production'},
      {'enrollment_id': 'bad'},
      {'public_key_sha256': '00' * 32},
      {'credential_sha256': null},
    ]) {
      expect(
        () => FactoryStatus.fromJson(
          {...f.status('ready'), ...change},
          deviceId: f.unit().id,
          role: 'Link',
        ),
        throwsFormatException,
      );
    }
    expect(
      () => FactoryStatus.fromJson(
        {...f.status('pending'), 'credential_sha256': 'aa' * 32},
        deviceId: f.unit().id,
        role: 'Link',
      ),
      throwsFormatException,
    );
    expect(
      () => FactoryStatus.fromJson(
        f.status('not_enrolled'),
        deviceId: 'bad',
        role: 'Link',
      ),
      throwsFormatException,
    );
    expect(
      () => FactoryStatus.fromJson(
        f.status('not_enrolled'),
        deviceId: f.unit().id,
        role: 'Other',
      ),
      throwsFormatException,
    );
  });
  group('real-file factory state', () {
    late Directory dir;
    late EvidenceJournal journal;
    late f.FactoryFake gateway;
    late FactoryController c;
    bool current = true;
    FactoryController controller({
      DeviceRecord? device,
      String role = 'Link',
    }) => FactoryController(
      gateway,
      journal,
      account: f.account,
      device: device ?? f.unit(),
      role: role,
      isCurrent: () => current,
      createId: () => f.request,
    );
    setUp(() async {
      dir = await Directory.systemTemp.createTemp('c53-factory-');
      journal = EvidenceJournal(dir);
      gateway = f.FactoryFake();
      current = true;
      c = controller();
    });
    tearDown(() async {
      c.dispose();
      await dir.delete(recursive: true);
    });
    test('issue commits request before network, then status confirms; plaintext is never stored', () async {
      await c.refresh();
      expect(c.canIssue, isTrue);
      expect(c.canReveal, isFalse);
      await c.issue(f.proof);
      expect(c.status!.ready, isTrue);
      expect(c.message, contains('original private claim QR'));
      expect(c.privateQr, isNull);
      await c.reveal();
      expect(c.privateQr!.text, f.qrRow()['text']);
      c.hide();
      expect(c.privateQr, isNull);
      final contents = await Future.wait(
        (await dir
                .list(recursive: true)
                .where((x) => x is File)
                .cast<File>()
                .toList())
            .map((p) => p.readAsString()),
      );
      expect(contents.join(), isNot(contains('OCTATRACE-CLAIM-1:')));
      expect(contents.join(), isNot(contains('claim_secret')));
    });
    test('failed issuance/restart reuses durable request; fresh status read recovers', () async {
      await c.refresh();
      gateway.failure = StateError('secret diagnostic');
      await c.issue(f.proof);
      expect(gateway.requests, [f.request]);
      expect(c.message, isNot(contains('secret diagnostic')));
      final replacement = controller();
      gateway.failure = null;
      await replacement.refresh();
      await replacement.issue(f.proof);
      expect(gateway.requests, [f.request, f.request]);
      expect(replacement.status!.ready, isTrue);
      replacement.dispose();
    });
    test('cancelled and late issuance does not restore UI; a fresh view recovers Ready', () async {
      await c.refresh();
      gateway.holdIssue = Completer();
      final pending = c.issue(f.proof);
      while (gateway.issues == 0) {
        await Future<void>.delayed(Duration.zero);
      }
      c.hide(explanation: 'cancelled');
      gateway.state = 'ready';
      gateway.holdIssue!.complete({
        'public_key_sha256': f.qrFields()['public_key_sha256'],
      });
      await pending;
      expect(c.privateQr, isNull);
      expect(c.status!.ready, isFalse);
      expect(c.busy, isFalse);
      await c.refresh();
      expect(c.status!.ready, isTrue);
    });
    test('pending/ineligible/claimed/readiness failures cannot manufacture an issued code', () async {
      await c.reveal();
      expect(gateway.reveals, 0);
      await c.issue('bad');
      expect(gateway.issues, 0);
      await c.refresh();
      await c.issue('bad');
      expect(gateway.issues, 0);
      gateway.state = 'pending';
      await c.refresh();
      expect(c.status!.state, 'pending');
      gateway.issuedStatus = {'public_key_sha256': 'ff' * 32};
      await c.issue(f.proof);
      expect(c.status!.ready, isFalse);
      expect(c.privateQr, isNull);
      for (final d in [
        f.unit(state: 'reserved'),
        f.unit(state: 'retired'),
        f.unit(prefix: 'O'),
        f.unit(owner: f.account),
      ]) {
        final guarded = controller(device: d);
        await guarded.refresh();
        expect(guarded.canIssue, isFalse);
        if (d.ownerId != null) expect(guarded.canReveal, isTrue);
        guarded.dispose();
      }
      final wrongRole = controller(role: 'Other');
      expect(wrongRole.eligible, isFalse);
      wrongRole.dispose();
    });
    test('refresh/error and late reveal after hide/logout/dispose cannot expose secret', () async {
      gateway.state = 'ready';
      await c.refresh();
      await c.reveal();
      expect(c.privateQr, isNotNull);
      gateway.failure = SessionExpired();
      await c.refresh();
      expect(c.privateQr, isNull);
      expect(c.status, isNull);
      expect(c.message, contains('Sign in again'));
      gateway.failure = OperatorDenied();
      await c.refresh();
      expect(c.message, contains('Sign in again'));
      gateway.failure = null;
      await c.refresh();
      gateway.payload = 'bad';
      await c.reveal();
      expect(c.privateQr, isNull);
      gateway.payload = null;
      for (final mode in ['hide', 'account', 'dispose']) {
        final fresh = controller();
        await fresh.refresh();
        gateway.holdReveal = Completer();
        final response = fresh.reveal();
        await Future<void>.delayed(Duration.zero);
        if (mode == 'hide') {
          fresh.hide();
        } else if (mode == 'account') {
          current = false;
        } else {
          fresh.dispose();
        }
        gateway.holdReveal!.complete(f.qrRow()['text'] as String);
        await response;
        expect(fresh.privateQr, isNull);
        if (mode != 'dispose') fresh.dispose();
        current = true;
        gateway.holdReveal = null;
      }
    });
    test(
      'busy/status and post-journal cancellation guard every await boundary',
      () async {
        gateway.holdStatus = Completer();
        final response = c.refresh();
        await c.refresh();
        expect(gateway.statuses, 1);
        c.hide();
        gateway.holdStatus!.complete(f.status('ready'));
        await response;
        expect(c.status, isNull);
        gateway.holdStatus = null;
        current = false;
        await c.refresh();
        expect(gateway.statuses, 1);
        current = true;
        await c.refresh();
        gateway.holdStatus = Completer();
        final issuing = c.issue(f.proof);
        while (gateway.issues == 0) {
          await Future<void>.delayed(Duration.zero);
        }
        c.hide();
        gateway.holdStatus!.complete(f.status('ready'));
        await issuing;
        expect(c.status!.ready, isFalse);
      },
    );
  });
}
