import 'package:flutter/material.dart';

import 'dart:io';
import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'domain/workshop_controller.dart';
import 'services/bench_runner.dart';
import 'services/magic_links.dart';
import 'services/supabase_gateway.dart';
import 'services/evidence_journal.dart';
import 'ui/workshop_app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  const url = String.fromEnvironment('SUPABASE_URL');
  const key = String.fromEnvironment('SUPABASE_PUBLISHABLE_KEY');
  const firmware = String.fromEnvironment('WORKSHOP_FIRMWARE_ROOT');
  final valid = Uri.tryParse(url);
  final configured =
      valid?.scheme == 'https' &&
      valid?.host.isNotEmpty == true &&
      key.isNotEmpty;
  runApp(
    WorkshopApp(
      links: configured ? nativeMagicLinks() : null,
      controller: configured
          ? WorkshopController(
              SupabaseGateway(url, key),
              ProcessBenchRunner(firmware),
              EvidenceJournal(
                Directory(
                  '${Platform.environment['HOME']}/Library/Application Support/com.octatrace.workshop/evidence/${sha256.convert(utf8.encode(valid!.origin))}',
                ),
              ),
            )
          : null,
    ),
  );
}
