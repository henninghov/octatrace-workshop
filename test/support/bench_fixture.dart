import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/bench_sync.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';

import '../provisioning_test.dart' as usb;
import '../widget_test.dart' as fixtures;

class TestBenchStore implements BenchStore {
  TestBenchStore([this.real]);
  final BenchStore? real;
  final records = <String, Json>{};
  int? failGeneration;
  int? heldSaveGeneration;
  Completer<void>? heldSave, saveStarted;
  bool wrongRead = false, failExport = false;
  Completer<Json>? holdReopen;
  @override
  Future<void> saveBench(Json report) async {
    if (report['generation'] == heldSaveGeneration && heldSave != null) {
      if (saveStarted != null && !saveStarted!.isCompleted) {
        saveStarted!.complete();
      }
      await heldSave!.future;
    }
    if (report['generation'] == failGeneration) {
      throw const FileSystemException('disk full');
    }
    await real?.saveBench(report);
    records[report['id']] = jsonDecode(jsonEncode(report));
  }

  @override
  Future<Json> reopenBench(String account, String id) async {
    if (wrongRead) return {};
    if (holdReopen != null) return holdReopen!.future;
    return real != null ? await real!.reopenBench(account, id) : records[id]!;
  }

  @override
  Future<List<Json>> benchHistory(String account) async => real != null
      ? await real!.benchHistory(account)
      : records.values.toList().reversed.toList();
  @override
  Future<({String path, String digest, int bytes})> exportBench(
    Json report,
    String folder,
  ) async {
    if (failExport) throw const FileSystemException('export interrupted');
    return real != null
        ? await real!.exportBench(report, folder)
        : (path: 'test/export.json', digest: 'a' * 64, bytes: 123);
  }
}

class BenchFixture {
  BenchFixture(this.store, this.definition);
  final TestBenchStore store;
  final BenchDefinition definition;
  final gateway = usb.SetupGateway()..completed = true;
  final usbRunner = usb.SetupRunner();
  late Registry registry;
  BenchSync? sync;
  BenchDefinition? inspection;
  BenchDefinition? readiness;
  BenchDefinition? startupDiagnostics;
  StartupDiagnosticsReader? startupDiagnosticsReader;
  BenchDefinition? delivery;
  BenchDefinition? installation, intentStop, preparation;
  InstallationReader? installReader;
  PreparationReader? preparationReader;
  InspectionReader? readinessReader, inspectionReader;
  Object? credentialError;
  PublicFactoryCredential? overrideCredential;
  String publicKey = '04${'11' * 64}';
  Completer<String>? heldKey;
  Completer<void>? keyStarted;
  int keyLookups = 0;
  int credentials = 0, deliveryReads = 0;
  Completer<PublicFactoryCredential>? heldCredential;
  int ids = 0, reads = 0;
  String fingerprint = 'a' * 64;
  Completer<Json>? inventory, response;
  Object? error;
  bool seenRead = false, seenDiscovery = false;
  Future<void> init() async {
    registry = await gateway.load();
  }

  BenchSession session([String account = fixtures.actor]) => BenchSession(
    account,
    definition,
    store,
    (a, d) async {
      seenDiscovery = true;
      return inventory != null
          ? await inventory!.future
          : await usbRunner.execute(account: a, command: 'inventory');
    },
    usbRunner.cancel,
    (a, r, {onDiagnostic}) async {
      reads++;
      seenRead = true;
      onDiagnostic?.call({'bounded': 'synthetic runner diagnostic'});
      if (error != null) throw error!;
      return response != null
          ? await response!.future
          : {
              'device_id': r.device.id,
              'serial': r.device.serial,
              'role': r.build.role,
              'build': r.build.source,
            };
    },
    () async => fingerprint,
    () => '90510000-0000-4000-8000-${(++ids).toString().padLeft(12, '0')}',
    () => DateTime.utc(2026, 11, 20, 12, 0, ids),
    sync: sync,
    inspectionDefinition: inspection,
    readinessDefinition: readiness,
    startupDiagnosticsDefinition: startupDiagnostics,
    readStartupDiagnostics: startupDiagnosticsReader,
    deliveryDefinition: delivery,
    installationDefinition: installation,
    intentStopDefinition: intentStop,
    preparationDefinition: preparation,
    readInstallation: installReader,
    readPreparation: preparationReader,
    lookupCredential: (device, article, publicKey) async {
      credentials++;
      if (credentialError != null) throw credentialError!;
      if (overrideCredential != null) return overrideCredential!;
      if (heldCredential != null) return heldCredential!.future;
      return PublicFactoryCredential.fromJson(
        {
          'v': 1,
          'device_id': device.id,
          'role': article.role,
          'credential': '010203',
          'credential_sha256': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
        },
        deviceId: device.id,
        role: article.role,
        expectedDigest:
            '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
      );
    },
    readDelivery:
        (account, selection, publicKey, credential, {onDiagnostic}) async {
          deliveryReads++;
          onDiagnostic?.call({'bounded': 'signed proof only'});
          if (error != null) throw error!;
          return {
            'delivery_proof': {'envelope_sha256': credential.digest},
          };
        },
    readReadiness:
        readinessReader ??
        (account, selection, publicKey, {onDiagnostic}) async {
          reads++;
          return {
            'state': 'empty',
            'inspection': {'state': 'blank', 'sha256': '22' * 32},
          };
        },
    lookupPublicKey: (device, article) async {
      keyLookups++;
      if (heldKey == null) return publicKey;
      if (keyStarted != null && !keyStarted!.isCompleted) {
        keyStarted!.complete();
      }
      return await heldKey!.future;
    },
    readInspection:
        inspectionReader ??
        (account, selection, publicKey, {onDiagnostic}) async {
          reads++;
          onDiagnostic?.call({'bounded': 'synthetic inspection diagnostic'});
          if (error != null) throw error!;
          return {'state': 'blank', 'sha256': '22' * 32};
        },
  );
  Future<void> start(BenchSession s) =>
      s.start(registry.devices.single, registry.articles.single);
  Future<void> connected(BenchSession s) =>
      s.connected(registry.devices.single, registry.articles.single);
}
