import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/bench_session.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/bench_files.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';
import 'package:octatrace_workshop/services/provisioning_runner.dart';

// Run explicitly from Workshop with its firmware-owner checkout available.
void main() {
  final firmware = Directory(
    Platform.environment['WORKSHOP_BENCH_FIRMWARE'] ?? '../octatrace-firmware',
  ).absolute;
  final definition = BenchDefinition.fromSnapshot(
    File(BenchDefinition.asset).readAsStringSync(),
  );
  final vectors = jsonDecode(
    File('${firmware.path}/contracts/usb-provisioning/vectors.json')
        .readAsStringSync(),
  );
  final frame = vectors['signed']['frame'];
  for (final role in ['Link', 'Core']) {
    for (final fault in ['ready', 'malformed']) {
      test(
        '$role shared process, real local report and $fault synthetic serial response',
        () async {
          final root = await Directory.systemTemp.createTemp('bench-owner-');
          addTearDown(() => root.delete(recursive: true));
          final runner = ProcessProvisioningRunner(
            firmware.path,
            root,
            startProcess: (path, args) {
              return Process.start(
                path,
                [
                  '-B',
                  'tools/acceptance/bench_identity_port.py',
                  firmware.path,
                  ...args.skip(2),
                ],
                environment: {'BENCH_CASE': fault},
              );
            },
          );
          final device = DeviceRecord.fromJson({
            ...frame,
            'id': frame['device_id'],
            'provisioning_state': 'provisioned',
            'hardware_uid': frame['hardware'],
          });
          final article = ArticleRevision.fromJson({
            'id': frame['article_revision_id'],
            'article_id': frame['article_id'],
            'role': role,
            'name': 'Synthetic',
            'code': role,
            'revision': 1,
            'case_version': 'A',
            'parts': [],
          });
          final store = EvidenceJournal(Directory('${root.path}/private'));
          final s = BenchSession(
            '90510000-0000-4000-8000-000000000001',
            definition,
            store,
            runner.discoverBench,
            runner.cancel,
            runner.readBenchIdentity,
            () async => 'a' * 64,
            () => '90510000-0000-4000-8000-000000000002',
            () => DateTime.utc(2026, 11, 20),
          );
          await s.start(device, article);
          await s.connected(device, article);
          final raw = jsonDecode(s.report!['artifacts'].single['content']);
          expect(raw['command'], 'identity');
          expect(raw['exit_code'], fault == 'ready' ? 0 : 1);
          if (fault == 'ready') {
            await s.observe(device.serial);
          } else {
            expect(s.report!['steps'][4]['status'], 'Not run');
            expect(
              utf8.decode(base64Decode(raw['stderr_base64'])),
              contains('Malformed JSON'),
            );
          }
          final export = await s.export(root.path);
          final saved = readBenchEnvelope(
            await File(export).readAsString(),
            s.account,
            s.report!['id'],
          );
          expect(saved['outcome'], fault == 'ready' ? 'Passed' : 'Failed');
          expect(saved['firmware']['role'], role);
        },
      );
    }
  }
}
