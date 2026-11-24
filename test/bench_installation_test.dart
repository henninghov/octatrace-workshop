import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'bench_session_test.dart';

BenchDefinition installDefinition(String path) =>
    BenchDefinition.fromSnapshot(File(path).readAsStringSync());

class InstallationFixture {
  InstallationFixture(BenchStore store)
    : f = BenchFixture(
        TestBenchStore(store),
        installDefinition(BenchDefinition.asset),
      );
  final BenchFixture f;
  late BenchSession s;
  Completer<void> reviewed = Completer<void>();
  Completer<void>? holdResult;
  int writes = 0;
  String? restartState, restartBoot;
  bool restartWrongContent = false;
  Object? restartError;
  Json review = {
    'review_token': 'a' * 64,
    'attempt_id': 'synthetic',
    'expires_ms': 25000,
    'review': {
      'boot': 'aa' * 16,
      'fault': 0,
      'credential_revision': 1,
      'content_id': 'cc' * 32,
      'serial': 'D000000000123',
      'role': 'Link',
      'envelope_sha256': 'dd' * 32,
      'slots_used': 0,
      'journal_state': 'empty',
    },
  };
  Future<void> init({bool stop = false, bool preparation = false}) async {
    await f.init();
    f.installation = installDefinition(BenchDefinition.installationAsset);
    f.intentStop = installDefinition(BenchDefinition.intentStopAsset);
    f.preparation = installDefinition(BenchDefinition.preparationAsset);
    f.installReader = (a, r, k, c, id, fault, confirm, {onDiagnostic}) async {
      review['review']['fault'] = fault;
      final reply = await confirm({...review, 'attempt_id': id});
      if (reply['confirm'] != true) throw BenchCancelled();
      expect(
        f.store.records[id]!['installation_consent']['status'],
        'Approved',
      );
      writes++;
      await holdResult?.future;
      onDiagnostic?.call({'public_proofs': 'retained'});
      return {
        'installation_proof': {
          'boot': 'aa' * 16,
          'credential_revision': 1,
          'content_id': 'cc' * 32,
          'journal_state': fault == 1 ? 'pending' : 'ready',
        },
      };
    };
    f.preparationReader = (a, r, k, id, confirm, {onDiagnostic}) async {
      final reply = await confirm({
        'inspection': {
          'boot': 'aa' * 16,
          'state': 'unknown',
          'sha256': 'dd' * 32,
        },
        'attempt_id': id,
        'review_token': 'a' * 64,
        'expires_ms': 25000,
      });
      if (reply['confirm'] != true) throw BenchCancelled();
      onDiagnostic?.call({'preparation': 'public readback diagnostic'});
      writes++;
      return {
        'preparation_result': {'boot': 'aa' * 16, 'state': 'blank'},
      };
    };
    Future<Json> restart(
      String a,
      ProvisionedIdentityRead r,
      String k, {
      void Function(Json)? onDiagnostic,
    }) async {
      if (restartError != null) throw restartError!;
      onDiagnostic?.call({'restart': 'public diagnostic'});
      return {
        'boot': restartBoot ?? 'bb' * 16,
        'state':
            restartState ??
            (preparation
                ? 'blank'
                : stop
                ? 'pending'
                : 'ready'),
        'revision': 1,
        'content_id': restartWrongContent ? 'ff' * 32 : 'cc' * 32,
      };
    }

    f.readinessReader = restart;
    f.inspectionReader = restart;
    s = f.session();
    s.selectDefinition(
      preparation
          ? f.preparation!
          : stop
          ? f.intentStop!
          : f.installation!,
    );
    s.onChanged = () {
      if (s.installationReview != null && !reviewed.isCompleted) {
        reviewed.complete();
      }
    };
  }

  Future<void> start() => f.start(s);
  Future<void> run() => s.perform(() => f.connected(s));
  Future<void> approve(bool accepted) async {
    await reviewed.future;
    await s.respondInstallation(accepted);
  }
}

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
  for (final mode in [
    'same boot',
    'wrong state',
    'wrong content',
    'transport error',
  ]) {
    test('restart $mode remains explicit and cannot pass', () async {
      await f.init();
      await f.start();
      final operation = f.run();
      await f.approve(true);
      await operation;
      if (mode == 'same boot') f.restartBoot = 'aa' * 16;
      if (mode == 'wrong state') f.restartState = 'empty';
      if (mode == 'wrong content') f.restartWrongContent = true;
      if (mode == 'transport error') {
        f.restartError = const FormatException('Disconnected');
      }
      await f.s.checkAfterRestart(confirmed: true);
      expect(f.s.report!['steps'][4]['status'], 'Failed');
    });
  }
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
  test('changed registry key before restart cannot pass', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.approve(true);
    await operation;
    f.f.publicKey = '04${'ff' * 64}';
    await f.s.checkAfterRestart(confirmed: true);
    expect(f.s.report!['outcome'], 'Failed');
  });
  test('restart confirmation is required and saved before reading', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.approve(true);
    await operation;
    await expectLater(f.s.observe('ready'), throwsStateError);
    await expectLater(
      f.s.checkAfterRestart(confirmed: false),
      throwsStateError,
    );
    expect(f.s.report!['steps'][4]['status'], 'Not run');
    final generation = f.s.report!['generation'] as int;
    f.f.store.failGeneration = generation + 1;
    await expectLater(
      f.s.checkAfterRestart(confirmed: true),
      throwsA(isA<FileSystemException>()),
    );
    expect(
      f.s.pending!['steps'][4]['evidence']['restart_confirmation']['confirmed'],
      true,
    );
    expect(
      f.s.pending!['steps'][4]['evidence']['automatic_restart_check'],
      isNull,
    );
    f.f.store.failGeneration = null;
    await f.s.retrySave();
    expect(f.s.report!['steps'][4]['status'], 'Not run');
  });
  test('a missing baseline cannot start restart verification', () async {
    await f.init();
    await f.start();
    f.s.report!['steps'][2]['status'] = 'Passed';
    f.s.report!['steps'][3]['status'] = 'Passed';
    await expectLater(f.s.checkAfterRestart(confirmed: true), throwsStateError);
    expect(f.writes, 0);
  });
  test(
    'a failed comparison retains the measured result and useful reason',
    () async {
      await f.init();
      await f.start();
      final operation = f.run();
      await f.approve(true);
      await operation;
      f.restartBoot = 'aa' * 16;
      await f.s.checkAfterRestart(confirmed: true);
      final evidence = f.s.report!['steps'][4]['evidence'];
      expect(evidence['automatic_restart_check']['boot'], 'aa' * 16);
      expect(evidence['automatic_error'], contains('baseline boot'));
      expect(evidence.containsKey('observation'), false);
    },
  );
  test('expired access retains incomplete evidence and propagates denial', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.approve(true);
    await operation;
    f.f.heldKey = Completer<String>();
    f.f.keyStarted = Completer<void>();
    final check = f.s.checkAfterRestart(confirmed: true);
    final denied = expectLater(check, throwsA(isA<SessionExpired>()));
    await f.f.keyStarted!.future;
    f.f.heldKey!.completeError(SessionExpired());
    await denied;
    expect(f.s.report!['outcome'], 'Interrupted');
    expect(f.s.report!['steps'][4]['status'], 'Incomplete');
    expect(
      f.s.report!['steps'][4]['evidence']['restart_confirmation']['confirmed'],
      true,
    );
  });
  test(
    'logout during confirmation save prevents registry and USB reads',
    () async {
      await f.init();
      await f.start();
      final operation = f.run();
      await f.approve(true);
      await operation;
      final lookups = f.f.keyLookups;
      f.f.store.heldSaveGeneration = (f.s.report!['generation'] as int) + 1;
      f.f.store.heldSave = Completer<void>();
      f.f.store.saveStarted = Completer<void>();
      final check = f.s.perform(() => f.s.checkAfterRestart(confirmed: true));
      await f.f.store.saveStarted!.future;
      final stopped = f.s.stop('Operator signed out');
      f.f.store.heldSave!.complete();
      await check;
      await stopped;
      expect(f.f.keyLookups, lookups);
      expect(f.s.report!['outcome'], 'Interrupted');
      expect(
        f.s.report!['steps'][4]['evidence']['automatic_restart_check'],
        isNull,
      );
    },
  );
  test('logout while rechecking registry prevents another USB read', () async {
    await f.init();
    await f.start();
    final operation = f.run();
    await f.approve(true);
    await operation;
    f.f.heldKey = Completer<String>();
    final check = f.s.perform(() => f.s.checkAfterRestart(confirmed: true));
    await Future<void>.delayed(Duration.zero);
    final stop = f.s.stop('Operator signed out');
    f.f.heldKey!.complete(f.f.publicKey);
    await check;
    await stop;
    expect(f.s.report!['outcome'], 'Interrupted');
  });
}
