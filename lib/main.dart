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
  final provisioner = ProcessProvisioningRunner(
    firmware,
    evidenceRoot,
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
    'assets/bench/claimed-firmware-update.v4.json',
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
              claimedUpdateFactory: (account, device, article, current) =>
                  ClaimedUpdateSession(
                    account: account,
                    device: device,
                    article: article,
                    gateway: gateway,
                    runner: provisioner,
                    prove: provisioner.proveUpdateIdentity,
                    store: journal,
                    definition: inspectionDefinition,
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
