import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'identity_preparation_test.dart' show FreshGateway;
import 'provisioning_test.dart' as p;
import 'widget_test.dart' as f;

class ControlPreparationRunner extends p.SetupRunner {
  String status = 'required', prepared = 'ready';
  Json? received;
  Object? prepareFailure;
  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    if (command == 'inspect-control-storage' ||
        command == 'prepare-control-storage') {
      commands.add(command);
      if (command == 'prepare-control-storage') {
        received = parameters;
        if (prepareFailure != null) throw prepareFailure!;
      }
      return p.preparationJson(
        parameters,
        status: command == 'inspect-control-storage' ? status : prepared,
      );
    }
    return super.execute(
      account: account,
      command: command,
      parameters: parameters,
    );
  }
}

void main() {
  late Directory tmp;
  late FreshGateway gateway;
  late ControlPreparationRunner runner;
  late WorkshopController c;
  Future<void> run({Future<bool> Function(StoragePreparation)? confirm}) =>
      c.provision(
        c.registry!.devices.single,
        c.registry!.articles.single,
        p.target,
        p.build,
        confirmPreparation: confirm,
      );
  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('workshop-control-');
    gateway = FreshGateway();
    runner = ControlPreparationRunner();
    c = WorkshopController(
      gateway,
      f.Runner(),
      EvidenceJournal(tmp),
      provisioner: runner,
      idFactory: () => p.requestId,
    );
    await f.signIn(c);
  });
  tearDown(() async {
    c.dispose();
    await c.closed;
    await tmp.delete(recursive: true);
  });
  test('blank and protected control journals need no confirmation', () async {
    for (final status in ['ready', 'preserved']) {
      runner.status = status;
      await run(confirm: (_) => throw StateError('Must not ask'));
      expect(c.provisioningOutcome, ProvisioningOutcome.successful);
      expect(runner.received, isNull);
    }
  });
  test('distinct confirmation reauthorizes same request after durable identity proof', () async {
    gateway.state = 'provisioned'; // Existing identities can prepare only their unknown control area.
    await c.refresh();
    await run(
      confirm: (context) async {
        expect(context.control, isTrue);
        expect(context.bytes, 8192);
        expect(runner.commands, [
          'inspect-storage',
          'provision',
          'inspect-control-storage',
        ]);
        expect(gateway.completes, 0);
        return true;
      },
    );
    expect(runner.received!['inspection_token'], 'd' * 64);
    expect(gateway.begins, [p.requestId, p.requestId]);
    expect(c.readbackSaved, isTrue);
    expect(c.provisioningOutcome, ProvisioningOutcome.successful);
  });
  test('missing or declined confirmation preserves reservation and stops preparation', () async {
    await run();
    await run(confirm: (_) async => false);
    expect(runner.received, isNull);
    expect(gateway.completes, 0);
    await c.syncEvidence();
    expect(gateway.completes, 0);
    expect(c.message, contains('Control storage verification is pending'));
  });
  test('changed registration binding key or completed state stops before preparation', () async {
    for (final change in [
      {'public_key': 'changed'},
      {'state': 'completed'},
      {'artifact': 'changed'},
    ]) {
      gateway.begins.clear();
      gateway.freshChange = change;
      await run(confirm: (_) async => true);
      expect(runner.received, isNull);
      expect(gateway.completes, 0);
    }
  });
  test(
    'logout while confirmation is open fences the destructive step',
    () async {
      await run(
        confirm: (_) async {
          await c.signOut();
          return true;
        },
      );
      expect(runner.received, isNull);
      expect(gateway.completes, 0);
    },
  );
  test(
    'failed preparation or nonblank readback cannot confirm provisioning',
    () async {
      runner.prepareFailure = const ProvisioningFailure(
        'Control preparation failed',
      );
      await run(confirm: (_) async => true);
      expect(c.provisioningOutcome, ProvisioningOutcome.failed);
      expect(gateway.completes, 0);
      runner.prepareFailure = null;
      runner.prepared = 'preserved';
      await run(confirm: (_) async => true);
      expect(c.message, contains('Control storage did not verify ready'));
      expect(gateway.completes, 0);
    },
  );
  test('control context cannot substitute an identity-area approval', () {
    final attempt = p.SetupGateway().attempt();
    final data = p.preparationJson(attempt, status: 'required');
    expect(
      () => StoragePreparation.fromJson(
        {...data, 'area': 'identity'},
        attempt,
        control: true,
      ),
      throwsFormatException,
    );
  });
}
