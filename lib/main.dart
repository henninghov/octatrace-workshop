import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'domain/bench_definition.dart';
import 'domain/bench_session.dart';
import 'domain/bench_sync.dart';
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
  final journal = EvidenceJournal(evidenceRoot);
  final provisioner = ProcessProvisioningRunner(firmware, evidenceRoot);
  final definition = BenchDefinition.fromSnapshot(
    await rootBundle.loadString(BenchDefinition.asset),
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
