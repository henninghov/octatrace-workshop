import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import 'bench_fixture.dart';

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
  int writes = 0, restartReads = 0;
  String? restartState, restartBoot;
  bool restartWrongContent = false, restartWrongRevision = false;
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
      restartReads++;
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
        'revision': restartWrongRevision ? 2 : 1,
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
