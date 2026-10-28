import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'widget_test.dart' as f;

const hardware = '1234567800000001';
const requestId = '40000000-0000-4000-8000-000000000001';
Json targetJson([String mode = 'app']) => {
  'hardware': hardware,
  'mode': mode,
  'label': 'Synthetic LINK · $mode',
  if (mode == 'bootloader') 'volume': '/Volumes/SYNTHETIC',
};
Json buildJson() => {
  'source': 'a' * 64,
  'artifact': 'b' * 64,
  'version': '0.2.0',
  'manifest': '/synthetic/build/firmware/link/${'a' * 64}/manifest.json',
  'label': '0.2.0 · LINK · aaaaaaaa',
};
final build = FirmwareBuild.fromJson(buildJson());
final target = UsbTarget.fromJson(targetJson());
Json proof() => {
  'before': {
    'boot': '1' * 32,
    'hardware': hardware,
    'public_key': '04${'a' * 128}',
  },
  'after': {
    'boot': '2' * 32,
    'hardware': hardware,
    'public_key': '04${'a' * 128}',
  },
};

Json preparationJson(Json parameters, {String status = 'ready'}) => {
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
    key: parameters[key],
  'role': parameters['role'] ?? 'Link',
  'status': status,
  'boot': '1' * 32,
  'profile': {
    'id': 'synthetic-profile-v1',
    'name': 'Synthetic board',
    'bytes': 8192,
  },
  if (status == 'required') 'inspection_token': 'd' * 64,
};

class SetupRunner implements ProvisioningRunner {
  final commands = <String>[];
  Completer<Json>? held;
  Completer<Json>? heldInventory, heldInstall;
  Object? failure;
  bool cancelFails = false, absent = false;
  int cancels = 0;
  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    commands.add(command);
    if (failure != null) throw failure!;
    if (command == 'inventory') {
      if (heldInventory != null) return heldInventory!.future;
      return {
        'targets': absent ? [] : [targetJson(), targetJson('bootloader')],
        'builds': absent ? [] : [buildJson()],
      };
    }
    if (command == 'inspect-storage' || command == 'prepare-storage') {
      return preparationJson(parameters);
    }
    if (command == 'install') {
      return heldInstall == null ? {'installed': true} : heldInstall!.future;
    }
    return held == null ? proof() : held!.future;
  }

  @override
  Future<void> cancel() async {
    cancels++;
    if (cancelFails) throw StateError('cancel failed');
  }
}

class SetupGateway extends f.Gateway implements ProvisioningGateway {
  final begins = <String>[];
  int completes = 0;
  String? state, hw;
  String product = 'Link';
  bool completed = false, loadFails = false, deny = false;
  String? mismatch;
  Object? failure;
  Completer<Json>? heldBegin;
  Completer<void>? heldComplete;
  Completer<Registry>? heldLoad;
  bool loading = false;
  Json? report;
  Registry Function()? loadOverride;
  @override
  Future<Registry> load() async {
    if (loadFails) throw StateError('load failed');
    if (heldLoad != null) {
      loading = true;
      return heldLoad!.future;
    }
    if (loadOverride != null) return loadOverride!();
    return Registry.fromJson({
      'articles': [
        {
          'id': f.revision,
          'article_id': 'article',
          'code': '${product.toUpperCase()}-TEST',
          'name': product.toUpperCase(),
          'role': product,
          'revision': 1,
          'case_version': 'A',
          'parts': [],
        },
      ],
      'devices': [
        {
          'id': f.device,
          'serial': 'D000000000001',
          'article_revision_id': f.revision,
          'provisioning_state':
              state ?? (completed ? 'provisioned' : 'reserved'),
          'hardware_uid': hw ?? (completed ? hardware : null),
          'owner_user_id': null,
          'firmware_version': completed ? '0.2.0' : null,
        },
      ],
      'runs': [],
    });
  }

  Json attempt() => {
    if (product == 'Core') 'role': product,
    'request_id': requestId,
    'device_id': f.device,
    'serial': 'D000000000001',
    'article_id': 'article',
    'article_revision_id': f.revision,
    'hardware': hardware,
    'source': build.source,
    'artifact': build.artifact,
    'challenge': 'c' * 64,
    'public_key': null,
    'state': completed ? 'completed' : 'started',
    'report': report ?? proof(),
    ?mismatch: 'conflict',
  };
  @override
  Future<Json> beginProvisioning({
    required String requestId,
    required String deviceId,
    required String hardware,
    required FirmwareBuild build,
  }) async {
    begins.add(requestId);
    if (deny) throw OperatorDenied();
    return heldBegin == null ? attempt() : heldBegin!.future;
  }

  @override
  Future<void> completeProvisioning({
    required String requestId,
    required String deviceId,
    required Json report,
  }) async {
    completes++;
    if (failure != null) throw failure!;
    await heldComplete?.future;
    completed = true;
    this.report = report;
  }
}

void main() {
  late Directory tmp;
  late EvidenceJournal journal;
  late SetupGateway gateway;
  late SetupRunner runner;
  late WorkshopController c;
  Future<void> run([
    UsbTarget? selected,
    DeviceRecord? device,
    ArticleRevision? article,
  ]) => c.provision(
    device ?? c.registry!.devices.single,
    article ?? c.registry!.articles.single,
    selected ?? target,
    build,
  );
  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('workshop-provisioning-');
    journal = EvidenceJournal(tmp);
    gateway = SetupGateway();
    runner = SetupRunner();
    c = WorkshopController(
      gateway,
      f.Runner(),
      journal,
      provisioner: runner,
      idFactory: () => requestId,
    );
    await f.signIn(c);
  });
  tearDown(() async {
    c.dispose();
    await c.closed;
    await tmp.delete(recursive: true);
  });

  test(
    'normal USB proves once, confirms fresh registry, retains synced proof',
    () async {
      expect(c.provisioningAvailable, isTrue);
      await c.discoverUsb();
      expect(c.usbInventory!.targets.length, 2);
      await run();
      expect(runner.commands, ['inventory', 'inspect-storage', 'provision']);
      expect(gateway.completes, 1);
      expect(c.registry!.devices.single.state, 'provisioned');
      expect(c.readbackSaved, isTrue);
      expect(c.pendingEvidence, 0);
      expect(await journal.pending(f.actor), isEmpty);
      expect(
        File('${tmp.path}/${f.actor}/synced/$requestId.json').existsSync(),
        isTrue,
      );
      expect(
        Directory('${tmp.path}/${f.actor}')
            .listSync()
            .where((e) => e.path.contains('reservation-')),
        isEmpty,
      );
    },
  );
  test(
    'bootloader install precedes proof and empty discovery stays explicit',
    () async {
      runner.absent = true;
      await c.discoverUsb();
      expect(c.usbInventory!.builds, isEmpty);
      await run(UsbTarget.fromJson(targetJson('bootloader')));
      expect(runner.commands, [
        'inventory',
        'install',
        'inspect-storage',
        'provision',
      ]);
      expect(c.readbackSaved, isTrue);
    },
  );
  test('cloud failure survives file reopen and uploads without USB', () async {
    gateway.failure = const ProvisioningFailure('Verifier unavailable');
    await run();
    expect(c.message, 'Verifier unavailable');
    expect(c.pendingEvidence, 1);
    expect(c.readbackSaved, isFalse);
    final reopened = EvidenceJournal(Directory(tmp.path));
    expect((await reopened.pending(f.actor)).single['id'], requestId);
    gateway.failure = null;
    runner.failure = StateError('USB must not be used');
    await c.syncEvidence();
    expect(c.readbackSaved, isTrue);
    expect(c.pendingEvidence, 0);
    expect(runner.commands, ['inspect-storage', 'provision']);
    expect(await reopened.pending(f.actor), isEmpty);
  });
  test('same attempt retry reuses UUID and immutable proof even if server key order differs', () async {
    gateway.failure = StateError('lost response');
    await run();
    gateway.completed = true;
    gateway.failure = null;
    final original = proof();
    gateway.report = {
      'after': Map.fromEntries(
        (original['after'] as Json).entries.toList().reversed,
      ),
      'before': Map.fromEntries(
        (original['before'] as Json).entries.toList().reversed,
      ),
    };
    await run();
    expect(gateway.begins, [requestId, requestId]);
    expect(runner.commands, ['inspect-storage', 'provision']);
    expect(c.readbackSaved, isTrue);
  });
  test(
    'fresh registry failure or disagreement retains pending proof',
    () async {
      gateway.state = 'reserved';
      await run();
      expect(c.message, contains('confirmation is incomplete'));
      expect(c.pendingEvidence, 1);
      gateway.state = null;
      gateway.hw = '8765432100000001';
      await c.syncEvidence();
      expect(c.message, contains('confirmation is incomplete'));
      gateway.hw = hardware;
      gateway.loadFails = true;
      await c.syncEvidence();
      expect(await journal.pending(f.actor), hasLength(1));
      gateway.loadFails = false;
      await c.syncEvidence();
      expect(c.pendingEvidence, 0);
    },
  );
  test('server refusal prevents any physical write', () async {
    gateway.deny = true;
    await run(UsbTarget.fromJson(targetJson('bootloader')));
    expect(runner.commands, isEmpty);
    expect(c.access, Access.denied);
    expect(await journal.pending(f.actor), isEmpty);
  });
  test('every server binding mismatch stops before USB', () async {
    for (final key in [
      'request_id',
      'device_id',
      'serial',
      'article_id',
      'article_revision_id',
      'hardware',
      'source',
      'artifact',
      'state',
    ]) {
      gateway.mismatch = key;
      await run();
      expect(runner.commands, isEmpty);
      expect(c.message, contains('does not match'));
    }
  });
  test(
    'wrong class, role, owner, retirement and bound hardware cannot start',
    () async {
      final base = {
        'id': f.device,
        'serial': 'D000000000001',
        'article_revision_id': f.revision,
        'provisioning_state': 'reserved',
      };
      for (final change in [
        {'serial': 'O000000000001'},
        {'owner_user_id': f.other},
        {'provisioning_state': 'retired'},
        {'hardware_uid': '8765432100000001'},
      ]) {
        await run(null, DeviceRecord.fromJson({...base, ...change}));
        expect(c.message, contains('unclaimed development device'));
      }
      final a = c.registry!.articles.single;
      await run(
        null,
        null,
        ArticleRevision.fromJson({
          'id': a.id,
          'article_id': a.articleId,
          'code': a.code,
          'name': a.name,
          'role': 'Core',
          'revision': 1,
          'case_version': 'A',
          'parts': [],
        }),
      );
      expect(gateway.begins, isEmpty);
      expect(runner.commands, isEmpty);
    },
  );
  test(
    'unsigned out account and unavailable runner do not provision',
    () async {
      final device = c.registry!.devices.single,
          article = c.registry!.articles.single;
      final legacy = WorkshopController(gateway, f.Runner(), journal);
      await f.signIn(legacy);
      await legacy.provision(device, article, target, build);
      expect(legacy.message, contains('unclaimed development device'));
      legacy.dispose();
      await legacy.closed;
      await c.signOut();
      await c.provision(device, article, target, build);
      expect(gateway.begins, isEmpty);
    },
  );
  test('cancel during server authorization prevents later install', () async {
    gateway.heldBegin = Completer();
    final future = run(UsbTarget.fromJson(targetJson('bootloader')));
    while (gateway.begins.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 1));
    }
    await c.cancel();
    gateway.heldBegin!.complete(gateway.attempt());
    await future;
    expect(runner.commands, isEmpty);
    expect(c.message, contains('Provisioning stopped'));
  });
  test('late proof after cancel is retained but never uploaded', () async {
    runner.held = Completer();
    final future = run();
    while (!runner.commands.contains('provision')) {
      await Future<void>.delayed(const Duration(milliseconds: 1));
    }
    await c.cancel();
    runner.held!.complete(proof());
    await future;
    expect(gateway.completes, 0);
    expect(await journal.pending(f.actor), hasLength(1));
    expect(c.pendingEvidence, 1);
  });
  test('logout isolates late proof in initiating account', () async {
    runner.held = Completer();
    final future = run();
    while (runner.commands.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 1));
    }
    await c.signOut();
    runner.held!.complete(proof());
    await future;
    expect(c.access, Access.signedOut);
    expect(c.readback, isNull);
    expect(c.usbInventory, isNull);
    expect(await journal.pending(f.actor), hasLength(1));
    expect(await journal.pending(f.other), isEmpty);
    expect(gateway.completes, 0);
  });
  test('logout during begin stops before touching USB', () async {
    gateway.heldBegin = Completer();
    final future = run();
    while (gateway.begins.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 1));
    }
    await c.signOut();
    gateway.heldBegin!.complete(gateway.attempt());
    await future;
    expect(runner.commands, isEmpty);
  });
  test(
    'USB failure keeps reservation and retry uses its original ID',
    () async {
      runner.failure = StateError('unplugged');
      await run();
      expect(c.message, contains('retained'));
      runner.failure = null;
      await run();
      expect(gateway.begins, [requestId, requestId]);
      expect(c.readbackSaved, isTrue);
    },
  );
  test('signout still clears auth when provisioner cancel fails', () async {
    runner.cancelFails = true;
    await c.signOut();
    expect(gateway.accountId, isNull);
    runner.cancelFails = false;
  });
  test('USB discovery remains available during a cloud outage', () async {
    // Inventory is read only and is independently allowed when the cloud is down.
    gateway.loadFails = true;
    await c.discoverUsb();
    expect(c.usbInventory, isNotNull);
    expect(c.message, isNull);
  });
  test('fresh registry must actually contain the selected device', () async {
    gateway.loadOverride = () =>
        Registry.fromJson({'articles': [], 'devices': [], 'runs': []});
    final device = c.registry!.devices.single,
        article = c.registry!.articles.single;
    await c.provision(device, article, target, build);
    expect(c.message, contains('confirmation is incomplete'));
  });
  test('late inventory after logout is ignored', () async {
    runner.heldInventory = Completer();
    final future = c.discoverUsb();
    while (runner.commands.isEmpty) {
      await Future<void>.delayed(Duration.zero);
    }
    await c.signOut();
    runner.heldInventory!.complete({
      'targets': [targetJson()],
      'builds': [buildJson()],
    });
    await future;
    expect(c.usbInventory, isNull);
    expect(c.registry, isNull);
  });
  test(
    'cancelling during installation never starts identity creation',
    () async {
      runner.heldInstall = Completer();
      final future = run(UsbTarget.fromJson(targetJson('bootloader')));
      while (!runner.commands.contains('install')) {
        await Future<void>.delayed(Duration.zero);
      }
      await c.cancel();
      runner.heldInstall!.complete({'installed': true});
      await future;
      expect(runner.commands, ['install']);
      expect(gateway.completes, 0);
      expect(c.message, contains('Provisioning stopped'));
    },
  );
  test(
    'logout during proof upload retains the original account outbox',
    () async {
      gateway.failure = StateError('offline');
      await run();
      gateway.failure = null;
      gateway.heldComplete = Completer();
      final future = c.syncEvidence();
      while (gateway.completes < 2) {
        await Future<void>.delayed(Duration.zero);
      }
      await c.signOut();
      gateway.heldComplete!.complete();
      await future;
      expect(c.registry, isNull);
      expect(await journal.pending(f.actor), hasLength(1));
      expect(await journal.pending(f.other), isEmpty);
      gateway.heldComplete = null;
      await f.signIn(c);
      await c.syncEvidence();
      expect(await journal.pending(f.actor), isEmpty);
    },
  );
  test(
    'logout during refreshed registry cannot acknowledge old proof',
    () async {
      gateway.failure = StateError('offline');
      await run();
      gateway.failure = null;
      gateway.heldLoad = Completer();
      final future = c.syncEvidence();
      while (!gateway.loading) {
        await Future<void>.delayed(Duration.zero);
      }
      final snapshot = f.data();
      await c.signOut();
      gateway.heldLoad!.complete(snapshot);
      await future;
      expect(c.registry, isNull);
      expect(await journal.pending(f.actor), hasLength(1));
    },
  );
  test(
    'new sign-in after revocation clears the previous inventory and status',
    () async {
      await c.discoverUsb();
      gateway.deny = true;
      await run();
      expect(c.access, Access.denied);
      expect(c.usbInventory, isNotNull);
      await c.requestLink('next-operator@example.invalid');
      expect(c.usbInventory, isNull);
      expect(c.readback, isNull);
      expect(c.pendingEvidence, 0);
    },
  );
  test('inventory and models reject ambiguity and malformed identity', () {
    expect(
      () => UsbTarget.fromJson({...targetJson(), 'hardware': '0' * 16}),
      throwsFormatException,
    );
    expect(
      () => UsbTarget.fromJson({...targetJson(), 'mode': 'other'}),
      throwsFormatException,
    );
    expect(
      () =>
          UsbTarget.fromJson({...targetJson('bootloader'), 'volume': '/wrong'}),
      throwsFormatException,
    );
    for (final key in ['source', 'artifact', 'version', 'role']) {
      expect(
        () => FirmwareBuild.fromJson({...buildJson(), key: 'bad'}),
        throwsFormatException,
      );
    }
    expect(
      () => UsbInventory.fromJson({
        'targets': [targetJson(), targetJson()],
        'builds': [],
      }),
      throwsFormatException,
    );
    expect(
      () => UsbInventory.fromJson({
        'targets': [],
        'builds': [buildJson(), buildJson()],
      }),
      throwsFormatException,
    );
  });
  test('CORE verifies the same identity with matching firmware and explicit server role', () async {
    gateway.product = 'Core';
    await c.refresh();
    final coreBuild = FirmwareBuild.fromJson({...buildJson(), 'role': 'Core'});
    final device = c.registry!.devices.single;
    final article = c.registry!.articles.single;
    await c.provision(device, article, target, coreBuild);
    expect(gateway.completed, isTrue);
    expect(c.readbackSaved, isTrue);
    expect(c.registry!.devices.single.id, device.id);
    expect(c.registry!.articles.single.role, 'Core');
    expect(runner.commands, ['inspect-storage', 'provision']);
    gateway.mismatch = 'role';
    await c.provision(c.registry!.devices.single, article, target, coreBuild);
    expect(c.message, contains('does not match'));
    expect(runner.commands, ['inspect-storage', 'provision']);
  });
  test(
    'inventory distinguishes role-specific builds at the same source revision',
    () {
      final inventory = UsbInventory.fromJson({
        'targets': [],
        'builds': [
          buildJson(),
          {...buildJson(), 'role': 'Core'},
        ],
      });
      expect(inventory.builds.map((b) => b.role), ['Link', 'Core']);
      expect(inventory.builds.map((b) => b.key).toSet(), hasLength(2));
    },
  );
}
