import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/services/bench_runner.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

const email = 'operator@example.invalid';

Future<void> signIn(WorkshopController c) async {
  await c.requestLink(email);
  await c.acceptLink(Uri.parse('$workshopCallback?code=synthetic'));
}

const actor = '10000000-0000-4000-8000-000000000001';
const other = '10000000-0000-4000-8000-000000000002';
const revision = '20000000-0000-4000-8000-000000000001';
const device = '30000000-0000-4000-8000-000000000001';
Registry data() => Registry.fromJson({
  'articles': [
    {
      'id': revision,
      'article_id': 'article',
      'code': 'LINK-TEST',
      'name': 'Synthetic LINK',
      'role': 'Link',
      'revision': 1,
      'case_version': 'A',
      'parts': [
        {'part_number': 'PCB-A', 'description': 'Board A', 'quantity': 1},
      ],
    },
  ],
  'devices': [
    {
      'id': device,
      'serial': 'D000000000001',
      'article_revision_id': revision,
      'provisioning_state': 'reserved',
      'owner_user_id': null,
      'firmware_version': null,
    },
  ],
  'runs': [],
});

class Gateway implements WorkshopGateway {
  bool denied = false, failSave = false, failReserve = false;
  Completer<Registry>? delayed;
  String? account = actor;
  String? pendingEmail;
  @override
  String? get accountEmail => pendingEmail;
  final requests = <String>[];
  int diagnostics = 0, articlesCreated = 0, revisionsCreated = 0;
  @override
  String? get accountId => account;
  @override
  Future<void> requestLink(String email) async {
    pendingEmail = email;
  }

  @override
  Future<void> exchangeLink(String code) async {
    account = actor;
  }

  @override
  Future<void> authorizeOperator() async {
    if (denied) throw OperatorDenied();
  }

  @override
  Future<void> signOut() async {
    account = null;
  }

  @override
  Future<Registry> load() async =>
      delayed == null ? data() : await delayed!.future;
  @override
  Future<void> reserve({
    required String requestId,
    required String revisionId,
    required String serialClass,
  }) async {
    requests.add(requestId);
    if (failReserve) throw StateError('network');
  }

  @override
  Future<void> recordDiagnostic({
    required String requestId,
    required String deviceId,
    required Json report,
  }) async {
    if (failSave) throw StateError('network');
    diagnostics++;
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
  }

  @override
  Future<void> addRevision({
    required String articleId,
    required String caseVersion,
    required List<Json> parts,
  }) async {
    revisionsCreated++;
  }

  @override
  Future<void> dispose() async {}
}

class Runner implements BenchRunner {
  bool cancelled = false;
  @override
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  }) async => {
    'provisioned': false,
    'device_id': null,
    'role': role,
    'build': build,
  };
  @override
  Future<void> cancel() async {
    cancelled = true;
  }
}

void main() {
  late Directory directory;
  late Gateway gateway;
  late Runner runner;
  late WorkshopController controller;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('workshop-test-');
    gateway = Gateway();
    runner = Runner();
    controller = WorkshopController(
      gateway,
      runner,
      EvidenceJournal(directory),
    );
  });
  tearDown(() async {
    controller.dispose();
    await directory.delete(recursive: true);
  });
  test('ordinary account denied and registry stays inaccessible', () async {
    gateway.denied = true;
    await signIn(controller);
    expect(controller.access, Access.denied);
    expect(controller.registry, isNull);
    expect(gateway.account, isNull);
  });
  test('late refresh cannot restore data after sign-out', () async {
    await signIn(controller);
    gateway.delayed = Completer<Registry>();
    final pending = controller.refresh();
    await Future<void>.delayed(Duration.zero);
    await controller.signOut();
    gateway.delayed!.complete(data());
    await pending;
    expect(controller.access, Access.signedOut);
    expect(controller.registry, isNull);
    expect(runner.cancelled, isTrue);
  });
  test('reservation retry identity survives controller restart', () async {
    await signIn(controller);
    gateway.failReserve = true;
    await controller.reserve(revision, 'D');
    final first = gateway.requests.single;
    final restarted = WorkshopController(
      gateway,
      runner,
      EvidenceJournal(directory),
    );
    await signIn(restarted);
    gateway.failReserve = false;
    await restarted.reserve(revision, 'D');
    expect(gateway.requests.last, first);
    restarted.dispose();
  });
  test('USB diagnostic is saved locally before cloud, retained on failure and logout', () async {
    await signIn(controller);
    gateway.failSave = true;
    await controller.verify(
      data().devices.single,
      data().articles.single,
      'port',
      'build',
    );
    final journal = EvidenceJournal(directory);
    expect((await journal.pending(actor)).length, 1);
    expect(controller.readbackSaved, isFalse);
    await controller.signOut();
    expect((await journal.pending(actor)).length, 1);
    expect(await journal.pending(other), isEmpty);
    gateway.failSave = false;
    await signIn(controller);
    await controller.syncEvidence();
    expect(await journal.pending(actor), isEmpty);
    expect(gateway.diagnostics, 1);
    expect(data().devices.single.state, 'reserved');
  });
  test(
    'journal rejects invalid account path and preserves evidence identity',
    () async {
      final journal = EvidenceJournal(directory);
      await expectLater(journal.pending('../escape'), throwsFormatException);
      await journal.save(actor, {
        'id': device,
        'report': {'a': 1},
      });
      await expectLater(
        journal.save(actor, {
          'id': device,
          'report': {'a': 2},
        }),
        throwsFormatException,
      );
      expect((await journal.pending(actor)).single['report'], {'a': 1});
    },
  );
  test('UUID requests have fixed binary UUID text shape', () {
    final ids = List.generate(100, (_) => newRequestId());
    expect(ids.toSet().length, 100);
    expect(
      ids.every(
        (s) => RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        ).hasMatch(s),
      ),
      isTrue,
    );
  });
  test('consumer verifies existing firmware-owned USB contract', () async {
    final runner = ProcessBenchRunner(Directory('vendor').absolute.path);
    await runner.verifyContract();
    await expectLater(
      runner.run(port: 'bad', role: 'Link', build: 'bad', command: 'identity'),
      throwsFormatException,
    );
    await expectLater(
      runner.run(
        port: '/dev/cu.usbmodem1',
        role: 'Link',
        build: 'a' * 64,
        command: 'flash',
      ),
      throwsFormatException,
    );
  });
  testWidgets('unconfigured app offers clear setup guidance, not fake login', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1100, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(const WorkshopApp(controller: null));
    await tester.pumpAndSettle();
    expect(find.textContaining('Configure the Supabase'), findsOneWidget);
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Send sign-in link'),
          )
          .onPressed,
      isNull,
    );
    await tester.tap(find.text('Dark mode'));
    await tester.pumpAndSettle();
    expect(find.text('Light mode'), findsOneWidget);
  });
  testWidgets(
    'reserved device exposes diagnostics and cannot be marked provisioned',
    (tester) async {
      await tester.runAsync(() => signIn(controller));
      tester.view.physicalSize = const Size(1100, 850);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(WorkshopApp(controller: controller));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Open device'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Registry status: reserved'), findsOneWidget);
      expect(
        tester
            .widget<OutlinedButton>(
              find.widgetWithText(OutlinedButton, 'Install and provision'),
            )
            .onPressed,
        isNull,
      );
      await tester.tap(find.text('Articles'));
      await tester.pumpAndSettle();
      expect(find.text('1 × PCB-A — Board A'), findsOneWidget);
    },
  );
}
