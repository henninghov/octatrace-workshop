import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'domain/bench_definition.dart';
import 'domain/bench_identity_key.dart';
import 'domain/bench_session.dart';
import 'domain/bench_sync.dart';
import 'domain/factory_credential_lookup.dart';
import 'domain/claimed_update.dart';
import 'services/bench_files.dart';

import 'dart:io';
import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'domain/workshop_controller.dart';
import 'services/bench_runner.dart';
import 'services/firmware_checks.dart';
import 'services/provisioning_runner.dart';
import 'services/magic_links.dart';
import 'services/supabase_gateway.dart';
import 'services/evidence_journal.dart';
import 'ui/workshop_app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  const url = String.fromEnvironment('SUPABASE_URL');
  const key = String.fromEnvironment('SUPABASE_PUBLISHABLE_KEY');
  const firmware = String.fromEnvironment('WORKSHOP_FIRMWARE_ROOT');
  const testPython = String.fromEnvironment('WORKSHOP_TEST_PYTHON');
  const firmwareFonts = String.fromEnvironment('WORKSHOP_FIRMWARE_FONTS');
  final valid = Uri.tryParse(url);
  final configured =
      valid?.scheme == 'https' &&
      valid?.host.isNotEmpty == true &&
      key.isNotEmpty;
  final evidenceRoot = Directory(
    '${Platform.environment['HOME']}/Library/Application Support/com.octatrace.workshop/evidence/${sha256.convert(utf8.encode(configured ? valid!.origin : 'unconfigured'))}',
  );
  final journal = EvidenceJournal(
    evidenceRoot,
    updateLocks: Directory('${evidenceRoot.parent.path}/update-locks'),
  );
  final authorityGuide = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.authorityAsset),
  );
  final provisioner = ProcessProvisioningRunner(
    firmware,
    evidenceRoot,
    factoryInspectionGuide: authorityGuide,
    updateProofProgram: await rootBundle.loadString(
      'assets/bench/claimed_update_proof.py',
    ),
  );
  final definition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.asset),
  );
  final inspectionDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.inspectionAsset),
  );
  final readinessDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.readinessAsset),
  );
  final startupDiagnosticsDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.startupDiagnosticsAsset),
  );
  final cryptoProbeDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.cryptoProbeAsset),
  );
  final cryptoReentryDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.cryptoReentryAsset),
  );
  final recoveryDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.recoveryAsset),
  );
  final pairedDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.pairedAsset),
  );
  final authorityPreparation = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.authorityPreparationAsset),
  );
  final authorityAvailable =
      configured &&
      firmware.isNotEmpty &&
      await provisioner.supportsAuthorityInspection(authorityGuide);
  final rtc2Definition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.rtc2Asset),
  );
  final cryptoKeysDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.cryptoKeysAsset),
  );
  final deliveryDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.deliveryAsset),
  );
  final installationDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.installationAsset),
  );
  final intentStopDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.intentStopAsset),
  );
  final preparationDefinition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.preparationAsset),
  );
  final updateGuide = await rootBundle.loadString(
    authorityAvailable
        ? 'assets/bench/claimed-firmware-update.v12.json'
        : 'assets/bench/claimed-firmware-update.v11.json',
  );
  final firmwareTestAdapter = await rootBundle.loadString(
    'tools/firmware_test_adapter.py',
  );
  final firmwareTestDefinition = await rootBundle.loadString(
    'assets/bench/firmware-host-regression.v8.json',
  );
  final gateway = configured ? SupabaseGateway(url, key) : null;
  runApp(
    WorkshopApp(
      links: configured ? nativeMagicLinks() : null,
      controller: configured
          ? WorkshopController(
              gateway!,
              ProcessBenchRunner(firmware),
              journal,
              provisioner: provisioner,
              firmwareChecks: ProcessFirmwareChecks(
                firmwareRoot: firmware,
                evidenceRoot: evidenceRoot,
                adapter: firmwareTestAdapter,
                definition: firmwareTestDefinition,
                newId: newRequestId,
                workshopFingerprint: () => workshopBundleFingerprint(),
              ),
              firmwareRoot: firmware,
              firmwarePython: testPython.isNotEmpty
                  ? testPython
                  : firmware.isEmpty
                  ? ''
                  : '$firmware/build/test-venv/bin/python',
              firmwareFonts: firmwareFonts,
              claimedUpdateFactory: (account, device, article, current) =>
                  ClaimedUpdateSession(
                    account: account,
                    device: device,
                    article: article,
                    gateway: gateway,
                    runner: provisioner,
                    prove: provisioner.proveUpdateIdentity,
                    store: journal,
                    definition: authorityAvailable
                        ? authorityGuide
                        : inspectionDefinition,
                    guideSnapshot: updateGuide,
                    newId: newRequestId,
                    now: DateTime.now,
                    workshopFingerprint: workshopBundleFingerprint,
                    current: current,
                  ),
              benchFactory: (account) => BenchSession(
                account,
                definition,
                journal,
                provisioner.discoverBench,
                provisioner.cancel,
                provisioner.readBenchIdentity,
                workshopBundleFingerprint,
                newRequestId,
                DateTime.now,
                inspectionDefinition: inspectionDefinition,
                readInspection: provisioner.readBenchInspection,
                readinessDefinition: readinessDefinition,
                readReadiness: provisioner.readBenchReadiness,
                startupDiagnosticsDefinition: startupDiagnosticsDefinition,
                readStartupDiagnostics: provisioner.readStartupDiagnostics,
                cryptoProbeDefinition: cryptoProbeDefinition,
                cryptoReentryDefinition: cryptoReentryDefinition,
                pairedDefinition: pairedDefinition,
                recoveryDefinition: recoveryDefinition,
                readPair: provisioner.readPairedHandshake,
                authorityDefinition: authorityAvailable ? authorityGuide : null,
                authorityPreparationDefinition: authorityPreparation,
                readAuthority: provisioner.readAuthority,
                rtc2Definition: rtc2Definition,
                readRtc2: provisioner.readRtc2,
                cryptoKeysDefinition: cryptoKeysDefinition,
                readCryptoProbe: provisioner.readCryptoProbe,
                deliveryDefinition: deliveryDefinition,
                readDelivery: provisioner.readBenchDelivery,
                installationDefinition: installationDefinition,
                intentStopDefinition: intentStopDefinition,
                readInstallation: provisioner.readBenchInstallation,
                preparationDefinition: preparationDefinition,
                readPreparation: provisioner.readBenchPreparation,
                lookupCredential: FactoryCredentialLookup(gateway).find,
                lookupPublicKey: IdentityKeyLookup(gateway).find,
                sync: BenchSync(
                  gateway.benchRpc,
                  journal.benchVerified,
                  journal.markBenchVerified,
                ),
              ),
            )
          : null,
    ),
  );
}
