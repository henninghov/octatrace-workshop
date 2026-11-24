import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'support/installation_fixture.dart';

void main() {
  late Directory root;
  late InstallationFixture f;
  setUp(() async {
    root = await Directory.systemTemp.createTemp('workshop-confirmation-');
    f = InstallationFixture(
      EvidenceJournal(Directory('${root.path}/evidence')),
    );
  });
  tearDown(() async => root.delete(recursive: true));
  for (final mode in ['install', 'stop', 'prepare']) {
    test(
      '$mode persists review and consent before write, verifies new boot and reopens',
      () async {
        await f.init(stop: mode == 'stop', preparation: mode == 'prepare');
        await f.start();
        final operation = f.run();
        await f.reviewed.future;
        expect(f.writes, 0);
        expect(
          f.f.store.records[f.s.report!['id']]!['installation_review'],
          isNotNull,
        );
        await f.approve(true);
        await operation;
        expect(f.writes, 1);
        expect(f.s.report!['steps'][3]['status'], 'Passed');
        await f.s.checkAfterRestart(confirmed: true);
        expect(
          f.s.report!['steps'][4]['evidence']['automatic_restart_check']['boot'],
          'bb' * 16,
        );
        expect(
          f.s.report!['steps'][4]['evidence']['restart_confirmation']['confirmed'],
          true,
        );
        await f.s.export(root.path);
        expect(f.s.report!['outcome'], 'Passed');
        final saved = await f.f.store.reopenBench(
          f.s.account,
          f.s.report!['id'],
        );
        expect(saved, f.s.report);
        expect(jsonEncode(saved), isNot(contains('010203')));
        await expectLater(f.s.respondInstallation(true), throwsStateError);
      },
    );
  }
  test('cancel and duplicate consent never write', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.approve(false);
    await operation;
    expect(f.writes, 0);
    expect(f.s.report!['outcome'], 'Incomplete');
    expect(f.s.report!['installation_consent']['status'], 'Cancelled');
    await expectLater(f.s.respondInstallation(true), throwsStateError);
  });
  for (final generation in [3, 4]) {
    test(
      'failed ${generation == 3 ? 'review' : 'consent'} save blocks write and retry only saves evidence',
      () async {
        await f.init();
        await f.start();
        f.f.store.failGeneration = generation;
        final operation = f.run();
        if (generation == 4) {
          await f.reviewed.future;
          await expectLater(
            f.s.respondInstallation(true),
            throwsA(isA<FileSystemException>()),
          );
        }
        await operation;
        expect(f.writes, 0);
        expect(f.s.pending, isNotNull);
        expect(
          f.s.pending!['installation_consent']['status'],
          'Not sent; local save failed',
        );
        f.f.store.failGeneration = null;
        await f.s.retrySave();
        expect(f.writes, 0);
        expect(f.s.report!['outcome'], 'Incomplete');
      },
    );
  }
  test(
    'operator authorization is refreshed before approving installation',
    () async {
      await f.init();
      await f.start();
      final operation = f.run();
      await f.reviewed.future;
      f.f.credentialError = const FormatException(
        'Operator authorization revoked',
      );
      await expectLater(f.s.respondInstallation(true), throwsFormatException);
      await operation;
      expect(f.writes, 0);
    },
  );
  test('changed original credential cancels confirmation', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.reviewed.future;
    final bytes = [1, 2, 4], digest = sha256.convert([1, 2, 4]).toString();
    f.f.overrideCredential = PublicFactoryCredential.fromJson(
      {
        'v': 1,
        'device_id': f.f.registry.devices.single.id,
        'role': 'Link',
        'credential': bytes
            .map((v) => v.toRadixString(16).padLeft(2, '0'))
            .join(),
        'credential_sha256': digest,
      },
      deviceId: f.f.registry.devices.single.id,
      role: 'Link',
      expectedDigest: digest,
    );
    await expectLater(f.s.respondInstallation(true), throwsA(isA<Exception>()));
    await operation;
    expect(f.writes, 0);
  });
  test(
    'preparation refreshes the independently verified registry key',
    () async {
      await f.init(preparation: true);
      await f.start();
      final operation = f.run();
      await f.reviewed.future;
      f.f.publicKey = '04${'ff' * 64}';
      await expectLater(
        f.s.respondInstallation(true),
        throwsA(isA<Exception>()),
      );
      await operation;
      expect(f.writes, 0);
    },
  );
  for (final reason in ['Operator cancelled', 'Operator signed out']) {
    test(
      '$reason releases pending confirmation without authorizing a write',
      () async {
        await f.init();
        await f.start();
        final operation = f.run();
        await f.reviewed.future;
        await f.s.stop(reason);
        await operation;
        expect(f.writes, 0);
        expect(f.s.installationReview, isNull);
        expect(f.s.report!['steps'][3]['status'], 'Incomplete');
        expect(
          f.s.report!['outcome'],
          reason == 'Operator cancelled' ? 'Cancelled' : 'Interrupted',
        );
      },
    );
  }
  test(
    'late installed result is retained after cancellation without a pass',
    () async {
      await f.init();
      f.holdResult = Completer<void>();
      await f.start();
      final operation = f.run();
      await f.approve(true);
      final stopping = f.s.stop('Operator signed out');
      f.holdResult!.complete();
      await operation;
      await stopping;
      expect(f.writes, 1);
      expect(f.s.report!['steps'][3]['status'], 'Incomplete');
      expect(f.s.report!['steps'][3]['evidence']['late_result'], isNotNull);
    },
  );
  test('recovery links the prior controlled-stop attempt', () async {
    await f.init(stop: true);
    await f.start();
    final operation = f.run();
    await f.approve(true);
    await operation;
    await f.s.checkAfterRestart(confirmed: true);
    await f.s.export(root.path);
    final stopped = f.s.report!['id'];
    f.s.selectDefinition(f.f.installation!);
    await f.start();
    expect(f.s.report!['recovery_of'], stopped);
    expect(f.s.history.length, 2);
  });
  test('a missing baseline cannot start restart verification', () async {
    await f.init();
    await f.start();
    f.s.report!['steps'][2]['status'] = 'Passed';
    f.s.report!['steps'][3]['status'] = 'Passed';
    await expectLater(f.s.checkAfterRestart(confirmed: true), throwsStateError);
    expect(f.writes, 0);
  });
}
