import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'provisioning_test.dart' as p;
import 'widget_test.dart' as f;

class PreparationRunner extends p.SetupRunner {
  String status = 'required', preparedStatus = 'ready';
  Json? received, inspectParameters;
  Completer<Json>? inspection;
  Object? preparationFailure;
  bool wrongBinding = false;
  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    if (command == 'inspect-storage' || command == 'prepare-storage') {
      commands.add(command);
      if (command == 'inspect-storage') {
        inspectParameters = parameters;
        if (inspection != null) return inspection!.future;
        return {
          ...p.preparationJson(parameters, status: status),
          if (wrongBinding) 'hardware': '0' * 16,
        };
      }
      received = parameters;
      if (preparationFailure != null) throw preparationFailure!;
      return p.preparationJson(parameters, status: preparedStatus);
    }
    return super.execute(
      account: account,
      command: command,
      parameters: parameters,
    );
  }
}

class FreshGateway extends p.SetupGateway {
  Json freshChange = {};
  @override
  Future<Json> beginProvisioning({
    required String requestId,
    required String deviceId,
    required String hardware,
    required FirmwareBuild build,
  }) async {
    final result = await super.beginProvisioning(
      requestId: requestId,
      deviceId: deviceId,
      hardware: hardware,
      build: build,
    );
    return begins.length > 1 ? {...result, ...freshChange} : result;
  }
}

void main() {
  late Directory tmp;
  late EvidenceJournal evidence;
  late PreparationRunner runner;
  late FreshGateway gateway;
  late WorkshopController c;
  int generated = 0;
  Future<void> run({Future<bool> Function(StoragePreparation)? confirm}) =>
      c.provision(
        c.registry!.devices.single,
        c.registry!.articles.single,
        p.target,
        p.build,
        confirmPreparation: confirm,
      );
  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('workshop-prepare-');
    evidence = EvidenceJournal(tmp);
    runner = PreparationRunner();
    gateway = FreshGateway();
    generated = 0;
    c = WorkshopController(
      gateway,
      f.Runner(),
      evidence,
      provisioner: runner,
      idFactory: () {
        generated++;
        return p.requestId;
      },
    );
    await f.signIn(c);
  });
  tearDown(() async {
    c.dispose();
    await c.closed;
    await tmp.delete(recursive: true);
  });
  test('blank and preserved storage continue without confirmation or initialization', () async {
    for (final status in ['ready', 'preserved']) {
      runner.status = status;
      await run(confirm: (_) => throw StateError('Must not ask'));
      expect(c.readbackSaved, isTrue);
      expect(runner.commands, isNot(contains('prepare-storage')));
      expect(c.provisioningOutcome, ProvisioningOutcome.successful);
    }
  });
  test(
    'confirmed preparation reauthorizes same request then confirms server',
    () async {
      await run(
        confirm: (context) async {
          expect(context.serial, 'D000000000001');
          expect(context.boardName, 'Synthetic board');
          expect(context.bytes, 8192);
          expect(c.provisioningOutcome, ProvisioningOutcome.pending);
          return true;
        },
      );
      expect(runner.commands, [
        'inspect-storage',
        'prepare-storage',
        'provision',
      ]);
      expect(runner.received!['inspection_token'], 'd' * 64);
      expect(gateway.begins, [p.requestId, p.requestId]);
      expect(generated, 1);
      expect(c.readbackSaved, isTrue);
    },
  );
  test(
    'declined or absent confirmation keeps real reservation for retry',
    () async {
      await run();
      expect(runner.received, isNull);
      expect(gateway.completes, 0);
      expect(c.provisioningOutcome, ProvisioningOutcome.pending);
      await run(confirm: (_) async => false);
      expect(generated, 1);
      expect(runner.commands, ['inspect-storage', 'inspect-storage']);
      await run(confirm: (_) async => true);
      expect(generated, 1);
      expect(c.readbackSaved, isTrue);
    },
  );
  test(
    'previously provisioned missing identity cannot offer preparation',
    () async {
      gateway.state = 'provisioned';
      await c.refresh();
      await run(confirm: (_) => throw StateError('Must not offer'));
      expect(runner.received, isNull);
      expect(c.message, contains('disabled'));
      expect(c.provisioningOutcome, ProvisioningOutcome.failed);
    },
  );
  test('preparation failure and failed readiness stop before creation or completion', () async {
    runner.preparationFailure = const ProvisioningFailure(
      'Preparation stopped',
    );
    await run(confirm: (_) async => true);
    expect(c.message, 'Preparation stopped');
    expect(gateway.completes, 0);
    runner.preparationFailure = null;
    runner.preparedStatus = 'preserved';
    await run(confirm: (_) async => true);
    expect(c.message, contains('did not verify ready'));
    expect(gateway.completes, 0);
    expect(runner.commands, isNot(contains('provision')));
    expect(generated, 1);
  });
  test('mismatched inspection stops before confirmation', () async {
    runner.wrongBinding = true;
    await run(confirm: (_) => throw StateError('Must not offer'));
    expect(runner.received, isNull);
    expect(gateway.completes, 0);
  });
  test('cancel or logout during consent cannot initialize afterward', () async {
    for (final logout in [false, true]) {
      final consent = Completer<bool>();
      final waiting = Completer<void>();
      final future = run(
        confirm: (_) {
          waiting.complete();
          return consent.future;
        },
      );
      await waiting.future;
      if (logout) {
        await c.signOut();
      } else {
        await c.cancel();
      }
      consent.complete(true);
      await future;
      expect(runner.received, isNull);
      expect(gateway.completes, 0);
    }
    expect(c.access, Access.signedOut);
    expect(c.provisioningOutcome, isNull);
  });
  test('revoked operator is rechecked after confirmation', () async {
    await run(
      confirm: (_) async {
        gateway.deny = true;
        return true;
      },
    );
    expect(runner.received, isNull);
    expect(c.access, Access.denied);
  });
  test(
    'changed key state and binding after consent stop before preparation',
    () async {
      for (final change in [
        {'state': 'completed'},
        {'public_key': 'registered'},
        {'artifact': 'changed'},
      ]) {
        gateway.begins.clear();
        gateway.freshChange = change;
        await run(confirm: (_) async => true);
        expect(runner.received, isNull);
        expect(gateway.completes, 0);
      }
    },
  );
  test('late inspection after cancellation cannot open confirmation', () async {
    runner.inspection = Completer<Json>();
    final future = run(confirm: (_) => throw StateError('Must not ask'));
    while (runner.inspectParameters == null) {
      await Future<void>.delayed(Duration.zero);
    }
    await c.cancel();
    runner.inspection!.complete(
      p.preparationJson(runner.inspectParameters!, status: 'required'),
    );
    await future;
    expect(runner.received, isNull);
  });
  test('failed confirmation retains proof; upload retry changes pending to successful', () async {
    runner.status = 'ready';
    gateway.failure = StateError('offline');
    await run();
    expect(c.provisioningOutcome, ProvisioningOutcome.failed);
    expect(c.readback, isNotNull);
    expect(c.pendingEvidence, 1);
    await c.syncEvidence();
    expect(c.provisioningOutcome, ProvisioningOutcome.failed);
    gateway.failure = null;
    gateway.heldComplete = Completer<void>();
    final upload = c.syncEvidence();
    while (c.provisioningOutcome != ProvisioningOutcome.pending) {
      await Future<void>.delayed(Duration.zero);
    }
    gateway.heldComplete!.complete();
    await upload;
    expect(c.provisioningOutcome, ProvisioningOutcome.successful);
    expect(c.pendingEvidence, 0);
    expect(c.readbackSaved, isTrue);
  });
  test('malformed preparation contexts are rejected', () {
    final attempt = p.SetupGateway().attempt();
    final valid = p.preparationJson(attempt, status: 'required');
    for (final change in [
      {'status': 'unknown'},
      {'boot': '0' * 32},
      {'role': 'Core'},
      for (final key in [
        'request_id',
        'device_id',
        'serial',
        'article_id',
        'article_revision_id',
        'hardware',
        'source',
        'artifact',
      ])
        {key: 'changed'},
      {'inspection_token': null},
      {'inspection_token': 'bad'},
      for (final patch in [
        {'id': null},
        {'id': ''},
        {'name': null},
        {'name': ''},
        {'bytes': 'x'},
        {'bytes': 0},
      ])
        {
          'profile': {...valid['profile'] as Json, ...patch},
        },
    ]) {
      expect(
        () => StoragePreparation.fromJson({...valid, ...change}, attempt),
        throwsFormatException,
      );
    }
  });
}
