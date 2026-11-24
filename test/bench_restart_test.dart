import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'support/bench_fixture.dart' as base;
import 'support/installation_fixture.dart';

enum RestartProcedure {
  installation('installation', 'ready'),
  controlledStop('controlled stop', 'pending'),
  preparation('preparation', 'blank'),
  readinessEmpty('readiness empty', 'empty'),
  readinessPending('readiness pending', 'pending'),
  readinessReady('readiness ready', 'ready');

  const RestartProcedure(this.label, this.expectedState);
  final String label;
  final String expectedState;
  bool get readOnly => name.startsWith('readiness');
}

class RestartFixture {
  RestartFixture(this.procedure);
  final RestartProcedure procedure;
  late final Directory root;
  late final base.BenchFixture baseFixture;
  late final BenchSession session;
  InstallationFixture? installation;
  int readinessReads = 0;
  String? restartState, restartBoot;
  bool wrongContent = false, wrongRevision = false;
  Object? restartError;

  int get restartReads => installation?.restartReads ?? readinessReads - 1;

  Future<void> start() async {
    root = await Directory.systemTemp.createTemp('workshop-restart-');
    final store = EvidenceJournal(Directory('${root.path}/evidence'));
    if (!procedure.readOnly) {
      final f = installation = InstallationFixture(store);
      await f.init(
        stop: procedure == RestartProcedure.controlledStop,
        preparation: procedure == RestartProcedure.preparation,
      );
      baseFixture = f.f;
      session = f.s;
      await f.start();
      final operation = f.run();
      await f.approve(true);
      await operation;
      expect(f.writes, 1);
    } else {
      final identity = BenchDefinition.fromSnapshot(
        File(BenchDefinition.asset).readAsStringSync(),
      );
      final f = baseFixture = base.BenchFixture(
        base.TestBenchStore(store),
        identity,
      );
      await f.init();
      f.readiness = BenchDefinition.fromSnapshot(
        File(BenchDefinition.readinessAsset).readAsStringSync(),
      );
      f.readinessReader = (account, selection, key, {onDiagnostic}) async {
        readinessReads++;
        final baseline = readinessReads == 1;
        if (!baseline && restartError != null) throw restartError!;
        onDiagnostic?.call({'restart': 'public diagnostic'});
        return {
          'state': baseline
              ? procedure.expectedState
              : restartState ?? procedure.expectedState,
          'boot': baseline ? 'aa' * 16 : restartBoot ?? 'bb' * 16,
          'revision': baseline || !wrongRevision ? 1 : 2,
          'content_id': !baseline && wrongContent ? 'ff' * 32 : 'cc' * 32,
        };
      };
      session = f.session();
      session.selectDefinition(f.readiness!);
      await f.start(session);
      await f.connected(session);
      expect(readinessReads, 1);
      expect(f.credentials, 0);
      expect(f.deliveryReads, 0);
    }
    expect(session.report!['steps'][3]['status'], 'Passed');
  }

  void failWith(String mode) {
    final otherState = procedure.expectedState == 'empty' ? 'pending' : 'empty';
    if (installation case final f?) {
      if (mode == 'same boot') f.restartBoot = 'aa' * 16;
      if (mode == 'wrong state') f.restartState = otherState;
      if (mode == 'wrong content') f.restartWrongContent = true;
      if (mode == 'wrong revision') f.restartWrongRevision = true;
      if (mode == 'disconnect') {
        f.restartError = const FormatException('Disconnected');
      }
    } else {
      if (mode == 'same boot') restartBoot = 'aa' * 16;
      if (mode == 'wrong state') restartState = otherState;
      if (mode == 'wrong content') wrongContent = true;
      if (mode == 'wrong revision') wrongRevision = true;
      if (mode == 'disconnect') {
        restartError = const FormatException('Disconnected');
      }
    }
  }

  Future<void> dispose() => root.delete(recursive: true);
}

void main() {
  for (final procedure in RestartProcedure.values) {
    group(procedure.label, () {
      late RestartFixture f;
      setUp(() async {
        f = RestartFixture(procedure);
        await f.start();
      });
      tearDown(() async => f.dispose());

      test('fresh matching restart saves confirmation and reopens', () async {
        await f.session.checkAfterRestart(confirmed: true);
        final steps = f.session.report!['steps'] as List;
        final evidence = steps[4]['evidence'];
        expect(steps[4]['status'], 'Passed');
        expect(steps[5]['status'], 'Passed');
        expect(evidence['restart_confirmation']['confirmed'], true);
        expect(evidence['expected_restart']['state'], procedure.expectedState);
        expect(evidence['expected_restart']['boot'], 'aa' * 16);
        expect(evidence['automatic_restart_check']['boot'], 'bb' * 16);
        expect(evidence['registry_check']['matched'], true);
        expect(evidence.containsKey('observation'), false);
        if (procedure.expectedState == 'ready') {
          expect(evidence['expected_restart']['revision'], 1);
          expect(evidence['expected_restart']['content_id'], 'cc' * 32);
          expect(evidence['automatic_restart_check']['revision'], 1);
          expect(evidence['automatic_restart_check']['content_id'], 'cc' * 32);
        }
        expect(f.restartReads, 1);
        if (procedure.readOnly) {
          expect(f.baseFixture.credentials, 0);
          expect(f.baseFixture.deliveryReads, 0);
          expect(f.baseFixture.usbRunner.commands, everyElement('inventory'));
        }
        await f.session.export(f.root.path);
        final reopened = await f.baseFixture.store.reopenBench(
          f.session.account,
          f.session.report!['id'],
        );
        expect(reopened, f.session.report);
      });

      for (final mode in [
        'same boot',
        'wrong state',
        'disconnect',
        if (procedure.expectedState == 'ready') 'wrong content',
        if (procedure.expectedState == 'ready') 'wrong revision',
      ]) {
        test('$mode retains failure and does not retry', () async {
          f.failWith(mode);
          await f.session.checkAfterRestart(confirmed: true);
          final step = f.session.report!['steps'][4];
          final evidence = step['evidence'];
          expect(step['status'], 'Failed');
          final expectedReason = switch (mode) {
            'same boot' => 'baseline boot',
            'wrong state' => 'measured state differs',
            'wrong content' ||
            'wrong revision' => 'credential revision or content differs',
            'disconnect' => 'Disconnected',
            _ => throw StateError('Unknown restart failure'),
          };
          expect(evidence['automatic_error'], contains(expectedReason));
          expect(evidence['restart_confirmation']['confirmed'], true);
          expect(evidence.containsKey('observation'), false);
          if (mode != 'disconnect') {
            expect(evidence['automatic_restart_check'], isNotNull);
          }
          if (mode == 'same boot') {
            expect(evidence['automatic_restart_check']['boot'], 'aa' * 16);
            expect(evidence['automatic_error'], contains('baseline boot'));
          }
          expect(f.restartReads, 1);
        });
      }

      test('changed registry key blocks the restart read', () async {
        f.baseFixture.publicKey = '04${'ff' * 64}';
        await f.session.checkAfterRestart(confirmed: true);
        expect(f.session.report!['outcome'], 'Failed');
        expect(
          f.session.report!['steps'][4]['evidence']['automatic_error'],
          contains('Registry'),
        );
        expect(f.restartReads, 0);
      });

      for (final (label, failure) in [
        (
          'identity or ownership change',
          const ProvisioningFailure('Registry identity or ownership changed.'),
        ),
        (
          'unavailable registry',
          const FormatException('Registry refresh unavailable'),
        ),
      ]) {
        test('$label blocks the restart read', () async {
          f.baseFixture.heldKey = Completer<String>();
          f.baseFixture.keyStarted = Completer<void>();
          final check = f.session.checkAfterRestart(confirmed: true);
          await f.baseFixture.keyStarted!.future;
          f.baseFixture.heldKey!.completeError(failure);
          await check;
          final step = f.session.report!['steps'][4];
          expect(step['status'], 'Failed');
          expect(step['evidence']['automatic_error'], contains('Registry'));
          expect(step['evidence']['restart_confirmation']['confirmed'], true);
          expect(f.restartReads, 0);
        });
      }

      test(
        'confirmation is required and a failed save blocks reading',
        () async {
          await expectLater(f.session.observe('ready'), throwsStateError);
          await expectLater(
            f.session.checkAfterRestart(confirmed: false),
            throwsStateError,
          );
          expect(f.session.report!['steps'][4]['status'], 'Not run');
          final generation = f.session.report!['generation'] as int;
          f.baseFixture.store.failGeneration = generation + 1;
          await expectLater(
            f.session.checkAfterRestart(confirmed: true),
            throwsA(isA<FileSystemException>()),
          );
          final evidence = f.session.pending!['steps'][4]['evidence'];
          expect(evidence['restart_confirmation']['confirmed'], true);
          expect(evidence['automatic_restart_check'], isNull);
          expect(f.restartReads, 0);
          f.baseFixture.store.failGeneration = null;
          await f.session.retrySave();
          expect(f.session.report!['steps'][4]['status'], 'Not run');
          expect(f.restartReads, 0);
        },
      );

      test(
        'failed result save retains measured evidence without retrying',
        () async {
          f.failWith('same boot');
          final generation = f.session.report!['generation'] as int;
          f.baseFixture.store.failGeneration = generation + 2;
          await expectLater(
            f.session.checkAfterRestart(confirmed: true),
            throwsA(isA<FileSystemException>()),
          );
          final evidence = f.session.pending!['steps'][4]['evidence'];
          expect(evidence['automatic_restart_check']['boot'], 'aa' * 16);
          expect(evidence['automatic_error'], contains('baseline boot'));
          expect(f.restartReads, 1);
          f.baseFixture.store.failGeneration = null;
          await f.session.retrySave();
          expect(f.session.report!['steps'][4]['status'], 'Failed');
          expect(f.restartReads, 1);
        },
      );

      for (final revoked in [false, true]) {
        test(
          '${revoked ? 'denied' : 'expired'} access retains incomplete evidence',
          () async {
            f.baseFixture.heldKey = Completer<String>();
            f.baseFixture.keyStarted = Completer<void>();
            final check = f.session.checkAfterRestart(confirmed: true);
            final failure = revoked
                ? isA<OperatorDenied>()
                : isA<SessionExpired>();
            final denied = expectLater(check, throwsA(failure));
            await f.baseFixture.keyStarted!.future;
            f.baseFixture.heldKey!.completeError(
              revoked ? OperatorDenied() : SessionExpired(),
            );
            await denied;
            expect(f.session.report!['outcome'], 'Interrupted');
            expect(f.session.report!['steps'][4]['status'], 'Incomplete');
            expect(
              f
                  .session
                  .report!['steps'][4]['evidence']['restart_confirmation']['confirmed'],
              true,
            );
            expect(f.restartReads, 0);
          },
        );
      }

      for (final reason in ['Operator cancelled', 'Operator signed out']) {
        test('$reason during confirmation save prevents reads', () async {
          final lookups = f.baseFixture.keyLookups;
          f.baseFixture.store.heldSaveGeneration =
              (f.session.report!['generation'] as int) + 1;
          f.baseFixture.store.heldSave = Completer<void>();
          f.baseFixture.store.saveStarted = Completer<void>();
          final check = f.session.perform(
            () => f.session.checkAfterRestart(confirmed: true),
          );
          await f.baseFixture.store.saveStarted!.future;
          final stopped = f.session.stop(reason);
          f.baseFixture.store.heldSave!.complete();
          await check;
          await stopped;
          expect(f.baseFixture.keyLookups, lookups);
          expect(
            f.session.report!['outcome'],
            reason == 'Operator cancelled' ? 'Cancelled' : 'Interrupted',
          );
          expect(
            f
                .session
                .report!['steps'][4]['evidence']['automatic_restart_check'],
            isNull,
          );
          expect(f.restartReads, 0);
        });

        test('$reason during registry refresh prevents reads', () async {
          f.baseFixture.heldKey = Completer<String>();
          f.baseFixture.keyStarted = Completer<void>();
          final check = f.session.perform(
            () => f.session.checkAfterRestart(confirmed: true),
          );
          await f.baseFixture.keyStarted!.future;
          final stopped = f.session.stop(reason);
          f.baseFixture.heldKey!.complete(f.baseFixture.publicKey);
          await check;
          await stopped;
          expect(
            f.session.report!['outcome'],
            reason == 'Operator cancelled' ? 'Cancelled' : 'Interrupted',
          );
          expect(f.restartReads, 0);
        });
      }
    });
  }
}
