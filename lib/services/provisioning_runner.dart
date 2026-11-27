import 'tool_environment.dart';

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/bench_definition.dart';
import '../domain/bench_session.dart';
import '../domain/factory_enrollment.dart';
import '../domain/ports.dart';
import '../domain/provisioning.dart';
import '../domain/registry.dart';

/// Thin process adapter; firmware owns USB, crypto, install guards and journal.
final class ProcessProvisioningRunner implements ProvisioningRunner {
  ProcessProvisioningRunner(
    this.firmwareRoot,
    this.evidenceRoot, {
    this.timeout = const Duration(seconds: 90),
    this.updateProofProgram,
    Future<Process> Function(String, List<String>)? startProcess,
    Future<String> Function(File) fileDigest = _fileDigest,
  }) : _digest = fileDigest,
       _startProcess =
           startProcess ??
           ((path, args) => Process.start(
             path,
             args,
             runInShell: false,
             environment: workshopToolEnvironment(),
           ));
  final String firmwareRoot;
  final Directory evidenceRoot;
  final Duration timeout;
  final String? updateProofProgram;
  final Future<Process> Function(String, List<String>) _startProcess;
  static Future<String> _fileDigest(File file) async =>
      sha256.convert(await file.readAsBytes()).toString();
  final Future<String> Function(File) _digest;
  Process? _process;
  bool _busy = false, _cancelled = false;
  static const pins = {
    "contracts/usb-provisioning/contract.json":
        "62414d301a437608c09f7693d06ad3167a6ae7f60d0c9e638153a0f98d0947c4",
    "contracts/usb-provisioning/proof.mjs":
        "e2738b810a1433190701788ed1940d7cb784702ef6af7f6c737ad6cc1fe292ab",
    "contracts/usb-provisioning/response.schema.json":
        "9e3af63f9b05ed41bb50011b134b7f7fa6d3d202b2df5203e568333a00c955e1",
    "contracts/usb-provisioning/vectors.json":
        "f4d7fd19a33e60883d60886c4ec10a46b1d37a2fde78a632038d902dabbc9361",
  };
  static const controlPins = {
    "contracts/control-storage/contract.json":
        "7d8015cbd7dfb41758780cbecc1649a78e7a56a9a0582a993d92b9edc5672f0e",
    "contracts/control-storage/response.schema.json":
        "2d73b8d5e74854b987f20a9dc4419fd83335a98b9956b0b20b769a7a73509dc7",
  };
  Future<void> verifyContract() async {
    final lock = jsonDecode(
      await File('$firmwareRoot/usb-provisioning.lock.json').readAsString(),
    ) as Map;
    final files = lock['files'];
    if (lock['version'] != 1 ||
        files is! Map ||
        files.length != pins.length ||
        pins.entries.any((e) => files[e.key] != e.value)) {
      throw const FormatException(
        'USB provisioning contract differs from Workshop',
      );
    }
    final controlLock = jsonDecode(
      await File('$firmwareRoot/control-storage.lock.json').readAsString(),
    ) as Map;
    if (controlLock['version'] != 1 ||
        controlLock['files'] is! Map ||
        (controlLock['files'] as Map).length != controlPins.length ||
        controlPins.entries.any(
          (e) => (controlLock['files'] as Map)[e.key] != e.value,
        )) {
      throw const FormatException(
        'Control storage contract differs from Workshop',
      );
    }
    for (final entry in {...pins, ...controlPins}.entries) {
      if (await _digest(File('$firmwareRoot/${entry.key}')) != entry.value) {
        throw const FormatException('USB provisioning contract hash mismatch');
      }
    }
  }

  Future<Json> discoverBench(String account, BenchDefinition definition) =>
      _execute(account, 'inventory', const {}, definition.runnerFiles);

  /// Fixed binding for the reviewed P1 catalog entry.
  Future<Json> readBenchIdentity(
    String account,
    ProvisionedIdentityRead read, {
    void Function(Json)? onDiagnostic,
  }) async {
    final frame = await _execute(
      account,
      'identity',
      read.parameters,
      read.definition.runnerFiles,
      onDiagnostic,
    );
    read.checkRegistryIdentity(frame);
    return frame;
  }

  Future<Json> readBenchInspection(
    String account,
    ProvisionedIdentityRead read,
    String publicKey, {
    void Function(Json)? onDiagnostic,
  }) async {
    final result = await _execute(
      account,
      'credential-inspection',
      read.inspectionParameters(publicKey),
      read.definition.runnerFiles,
      onDiagnostic,
    );
    _checkInspection(read, publicKey, result);
    return result;
  }

  void _checkInspection(
    ProvisionedIdentityRead read,
    String publicKey,
    Json result,
  ) {
    final proof = result['identity_proof'];
    if (proof is! Json ||
        result['v'] != 1 ||
        result['ok'] != true ||
        result['id'] is! int ||
        (result['id'] as int) <= 0 ||
        result['type'] != 'credential_storage' ||
        result['role'] != read.build.role ||
        result['build'] != read.build.source ||
        result['hardware'] != read.device.hardwareUid ||
        !{
          'blank',
          'unknown',
          'recognizable',
          'interrupted',
        }.contains(result['state']) ||
        result['busy'] != false ||
        result['failed'] != false ||
        result['last_request'] is! int ||
        (result['last_request'] as int) <= 0 ||
        result['sha256'] is! String ||
        !hexId(result['sha256'] as String, 64)) {
      throw const ProvisioningFailure(
        'Credential inspection returned an invalid result.',
      );
    }
    read.checkRegistryIdentity(proof);
    if (proof['role'] != read.build.role ||
        proof['build'] != read.build.source ||
        proof['hardware'] != read.device.hardwareUid ||
        proof['public_key'] != publicKey ||
        proof['boot'] != result['boot'] ||
        proof['boot'] is! String ||
        !hexId(proof['boot'] as String, 32) ||
        proof['boot'] == '0' * 32 ||
        proof['challenge'] is! String ||
        !hexId(proof['challenge'] as String, 64) ||
        proof['challenge'] == '0' * 64 ||
        proof['signature'] is! String ||
        !hexId(proof['signature'] as String, 128)) {
      throw const ProvisioningFailure(
        'Credential inspection proof does not match the selected device.',
      );
    }
  }

  Future<Json> readStartupDiagnostics(
    String account,
    ProvisionedIdentityRead read,
    String publicKey,
    String check, {
    void Function(Json)? onDiagnostic,
  }) async {
    if (!BenchSession.startupChecks.contains(check)) {
      throw const FormatException('Unknown startup diagnostic');
    }
    final result = await _execute(
      account,
      'startup-diagnostics',
      {'selection': read.inspectionParameters(publicKey), 'check': check},
      read.definition.runnerFiles,
      onDiagnostic,
    );
    if (result['selection'] != check ||
        !{'passed', 'failed'}.contains(result['outcome'])) {
      throw const ProvisioningFailure('Invalid startup diagnostics result.');
    }
    if (result['outcome'] == 'failed') return result;
    final before = result['before_proof'], after = result['after_proof'];
    final frame = result['frame'];
    if (before is! Json || after is! Json || frame is! Json) {
      throw const ProvisioningFailure(
        'Startup diagnostics evidence is incomplete.',
      );
    }
    for (final proof in [before, after]) {
      read.checkRegistryIdentity(proof);
      if (proof['role'] != read.build.role ||
          proof['build'] != read.build.source ||
          proof['hardware'] != read.device.hardwareUid ||
          proof['public_key'] != publicKey ||
          proof['boot'] is! String ||
          !hexId(proof['boot'] as String, 32) ||
          proof['boot'] == '0' * 32 ||
          proof['challenge'] is! String ||
          !hexId(proof['challenge'] as String, 64) ||
          proof['signature'] is! String ||
          !hexId(proof['signature'] as String, 128)) {
        throw const ProvisioningFailure(
          'Startup diagnostics identity proof does not match.',
        );
      }
    }
    final rows = frame['results'];
    if (before['boot'] != after['boot'] ||
        before['challenge'] == after['challenge'] ||
        frame['v'] != 1 ||
        frame['ok'] != true ||
        frame['type'] != 'tests' ||
        frame['role'] != read.build.role ||
        frame['build'] != read.build.source ||
        frame['run_id'] is! int ||
        (frame['run_id'] as int) <= 0 ||
        frame['running'] != false ||
        rows is! List ||
        rows.length != BenchSession.startupChecks.length - 1) {
      throw const ProvisioningFailure(
        'Startup diagnostics frame does not match.',
      );
    }
    for (var i = 0; i < rows.length; i++) {
      final row = rows[i];
      final name = BenchSession.startupChecks[i + 1];
      if (row is! Map ||
          row['id'] != name ||
          row['result'] !=
              (check == 'all' || check == name ? 'passed' : 'not_run')) {
        throw const ProvisioningFailure(
          'Startup diagnostics did not pass the selected checks.',
        );
      }
    }
    return result;
  }

  Future<Map<String, Json>> readPairedHandshake(
    String account,
    Map<String, ({ProvisionedIdentityRead read, String publicKey})> peers, {
    void Function(Json)? onDiagnostic,
  }) async {
    final link = peers['Link'], core = peers['Core'];
    if (peers.length != 2 ||
        link == null ||
        core == null ||
        link.read.build.role != 'Link' ||
        core.read.build.role != 'Core' ||
        link.read.build.source != core.read.build.source ||
        link.read.definition.snapshotDigest !=
            core.read.definition.snapshotDigest ||
        !link.read.definition.runnerFiles.containsKey(
          'tools/connection_bench.py',
        )) {
      throw const BenchBlocked(
        'Select the reviewed LINK and CORE pair procedure.',
      );
    }
    final recovery =
        link.read.definition.guide['key'] == BenchDefinition.recoveryKey;
    final result = await _execute(
      account,
      recovery ? 'connection-recovery' : 'connection-bench',
      {
        for (final p in peers.entries)
          p.key: p.value.read.inspectionParameters(p.value.publicKey),
      },
      link.read.definition.runnerFiles,
      onDiagnostic,
    );
    final rows = result['observations'];
    if (rows is! List || rows.isEmpty || rows.any((r) => r is! Json)) {
      throw const ProvisioningFailure(
        'The paired handshake record is incomplete.',
      );
    }
    final start = rows.first['start'];
    if (start is! Json ||
        start['definition'] !=
            (recovery
                ? 'c83-temporary-recovery.v1'
                : 'c83-permanent-peer-handshake.v1') ||
        start['carrier'] != 'supervised_usb' ||
        start['identity'] !=
            (recovery ? 'temporary_test' : 'provisioned_permanent') ||
        start['pair_sha256'] != link.read.definition.guide['pair_sha256'] ||
        start['attempt'] is! String ||
        !RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        ).hasMatch(start['attempt'] as String)) {
      throw const ProvisioningFailure(
        'Handshake identity or procedure binding differs.',
      );
    }
    final reports = <String, Json>{};
    final challenges = <String>{};
    for (final p in peers.entries) {
      final read = p.value.read;
      final roleRows = rows
          .whereType<Json>()
          .where((r) => r['role'] == p.key)
          .toList();
      final before = roleRows.firstOrNull?['before_proof'];
      final end = roleRows.lastOrNull;
      if (roleRows.length < 5 ||
          before is! Json ||
          end == null ||
          end['handshake'] != 'confirmed' ||
          end['attempt'] != start['attempt'] ||
          end['definition'] != start['definition'] ||
          end['source'] != read.build.source ||
          end['artifact'] != read.build.artifact ||
          end['generation'] is! int ||
          (end['generation'] as int) <= 0) {
        throw const ProvisioningFailure(
          'Missing role-specific handshake confirmation.',
        );
      }
      final after = roleRows[roleRows.length - 2]['after_proof'];
      if (after is! Json || before['boot'] != after['boot']) {
        throw const ProvisioningFailure(
          'Board boot changed during the handshake.',
        );
      }
      for (final proof in [before, after]) {
        read.checkRegistryIdentity(proof);
        if (proof['role'] != p.key ||
            proof['hardware'] != read.device.hardwareUid ||
            proof['public_key'] != p.value.publicKey ||
            proof['build'] != read.build.source ||
            !hexId(proof['boot'] as String? ?? '', 32) ||
            !hexId(proof['signature'] as String? ?? '', 128) ||
            !hexId(proof['challenge'] as String? ?? '', 64) ||
            !challenges.add(proof['challenge'] as String)) {
          throw const ProvisioningFailure(
            'USB proof differs from the registered peer.',
          );
        }
      }
      final measuredAt = roleRows.length - (recovery ? 3 : 4);
      final measurement = roleRows[measuredAt]['resources'];
      if (measurement is! Json ||
          measurement['role'] != p.key ||
          measurement['hardware'] != read.device.hardwareUid ||
          measurement['build'] != read.build.source ||
          measurement['boot'] != before['boot'] ||
          measurement['generation'] != end['generation'] ||
          measurement['type'] != 'c83_resources' ||
          measurement['heap_fault'] != false) {
        throw const ProvisioningFailure('Missing role-bound measurements.');
      }
      if (recovery) {
        await _verifyRecovery(roleRows, measurement);
      } else {
        var confirmed = false;
        final cancellation = roleRows[roleRows.length - 3];
        if (cancellation['operation'] != 'cancel' ||
            cancellation['status']?['state'] != 'cancelled') {
          throw const ProvisioningFailure(
            'Missing role-bound measurements or worker retirement.',
          );
        }
        for (final row in [
          ...roleRows.sublist(1, roleRows.length - 4),
          cancellation,
        ]) {
          final sample = row['status'];
          if (sample is! Json ||
              sample['build'] != read.build.source ||
              sample['hardware'] != read.device.hardwareUid ||
              sample['role'] != p.key ||
              sample['boot'] != before['boot'] ||
              sample['generation'] != end['generation'] ||
              sample['accepted'] != true ||
              sample['busy'] != false) {
            throw const ProvisioningFailure(
              'Worker completion belongs to another operation.',
            );
          }
          if (sample['state'] == 'confirmed' && sample['ticket'] == 0) {
            confirmed = true;
          }
        }
        if (!confirmed) {
          throw const ProvisioningFailure(
            'Board supplied no completed session confirmation.',
          );
        }
      }
      reports[p.key] = {
        if (recovery)
          'usb_minimum_free_bytes': roleRows
              .where((row) => row['resources'] != null)
              .map((row) => row['resources']['usb_free'] as int)
              .reduce((a, b) => a < b ? a : b),
        if (recovery)
          'recovery_cases': [
            for (final row in roleRows)
              if (row['case'] != null) row['case'],
          ],
        'attempt': start['attempt'],
        'definition': start['definition'],
        'carrier': start['carrier'],
        'identity': start['identity'],
        'peer_device_id':
            peers[p.key == 'Link' ? 'Core' : 'Link']!.read.device.id,
        'handshake': 'confirmed',
        'resources': measurement,
        'role_observations': roleRows,
        'exchange_sha256': benchHash(jsonEncode(rows)),
      };
    }
    if (recovery) {
      List<Object?> attempts(String role) => [
        for (final row in reports[role]!['role_observations'])
          if (row['recovered_after'] != null) row['attempt'],
      ];
      if (jsonEncode(attempts('Link')) != jsonEncode(attempts('Core'))) {
        throw const ProvisioningFailure(
          'Recovery attempts differ between the two boards.',
        );
      }
    }
    return reports;
  }

  static Future<void> _verifyRecovery(List<Json> rows, Json measurement) async {
    Never invalid() => throw const ProvisioningFailure(
      'Incomplete temporary-identity recovery evidence.',
    );
    bool bound(Json sample, Object? generation) =>
        sample['generation'] == generation &&
        [
          'role',
          'hardware',
          'build',
          'boot',
        ].every((k) => sample[k] == measurement[k]);

    const names = [
      'entropy',
      'deadline',
      'continuity',
      'cancel',
      'stale',
      'slots',
      'signing',
    ];
    final cases = rows.where((r) => r.containsKey('case')).toList();
    if (jsonEncode(cases.map((r) => r['case']).toList()) != jsonEncode(names)) {
      invalid();
    }
    final retries = rows
        .where((r) => r.containsKey('recovered_after'))
        .toList();
    final labels = [
      'entropy',
      'deadline',
      'continuity',
      for (final role in ['Link', 'Core']) ...[
        '$role-cancel-stale',
        '$role-slots',
        '$role-signing',
      ],
    ];
    if (retries.length != labels.length) invalid();
    final attempts = <String>{};
    final generations = <String, int>{};
    var last = 0;
    for (var i = 0; i < retries.length; i++) {
      final row = retries[i];
      final generation = row['generation'], attempt = row['attempt'];
      final sample = row['resources'], retirement = row['retirement'];
      final cooldown = row['radio_cooldown_refused'];
      if (generation is! int ||
          generation <= last ||
          attempt is! String ||
          !attempts.add(attempt) ||
          row['recovered_after'] != labels[i] ||
          jsonEncode(row['flights']) != '[1,2,3,4,5,6,7,8]' ||
          sample is! Json ||
          !bound(sample, generation) ||
          retirement is! Json ||
          !bound(retirement, generation) ||
          retirement['state'] != 'cancelled' ||
          retirement['temporary'] != true ||
          retirement['cleaned'] != true ||
          cooldown is! Json ||
          !bound(cooldown, generation) ||
          cooldown['accepted'] != true ||
          cooldown['temporary'] != true ||
          cooldown['state'] != 'active' ||
          sample['heap_fault'] != false ||
          sample['worker_free'] is! int ||
          sample['worker_free'] < 2048 ||
          sample['usb_free'] is! int ||
          sample['usb_free'] < 2048 ||
          sample['radio_reads'] is! int ||
          sample['radio_reads'] <= 0 ||
          sample['radio_reads'] != sample['flash_reads'] ||
          !hexId(row['observations_sha256'] as String? ?? '', 64)) {
        invalid();
      }
      generations[labels[i]] = generation;
      last = generation;
    }
    if (jsonEncode(retries.last['resources']) != jsonEncode(measurement)) {
      invalid();
    }
    for (final row in cases) {
      final name = row['case'];
      final sample = row['status'], generation = row['generation'];
      if (sample is! Json ||
          generation is! int ||
          !bound(sample, generation) ||
          sample['temporary'] != true ||
          sample['busy'] != false) {
        invalid();
      }
      final retry = const ['entropy', 'deadline', 'continuity'].contains(name)
          ? name as String
          : '${measurement['role']}-${name == 'stale' || name == 'cancel' ? 'cancel-stale' : name}';
      if (name == 'stale') {
        final cancellation = cases.singleWhere((c) => c['case'] == 'cancel');
        if (generation != generations[retry] ||
            sample['state'] != 'active' ||
            sample['accepted'] != true ||
            row['old_ticket'] is! int ||
            row['old_ticket'] <= 0 ||
            sample['ticket'] == 0 ||
            sample['ticket'] == row['old_ticket'] ||
            row['old_ticket'] != cancellation['borrowed_ticket'] ||
            row['old_generation'] != cancellation['generation']) {
          invalid();
        }
      } else {
        final memory = row['resources'];
        if (generation >= generations[retry]! ||
            !bound(sample, generation) ||
            sample['cleaned'] != true ||
            sample['accepted'] != (name == 'cancel') ||
            sample['ticket'] != 0 ||
            sample['fault'] !=
                const {
                  'entropy': 1,
                  'slots': 2,
                  'signing': 3,
                  'deadline': 4,
                  'continuity': 5,
                  'cancel': 0,
                }[name] ||
            sample['state'] != (name == 'cancel' ? 'cancelled' : 'failed') ||
            memory is! Json ||
            !bound(memory, generation) ||
            memory['heap_fault'] != false ||
            memory['usb_free'] is! int ||
            memory['usb_free'] < 2048 ||
            memory['worker_free'] is! int ||
            memory['worker_free'] < 2048) {
          invalid();
        }
      }
    }
    final trace = rows[rows.length - 4]['trace'];
    if (trace is! Json ||
        trace['encoding'] != 'zlib-base64-ndjson' ||
        trace['bytes'] is! int ||
        trace['bytes'] <= 0 ||
        trace['bytes'] > 2 * 1024 * 1024 ||
        trace['content'] is! String ||
        !hexId(trace['sha256'] as String? ?? '', 64) ||
        trace['sha256'] != retries.last['observations_sha256']) {
      invalid();
    }
    var count = 0;
    final raw = Stream<List<int>>.value(base64Decode(trace['content']))
        .transform(zlib.decoder)
        .map((chunk) {
          count += chunk.length;
          if (count > trace['bytes']) invalid();
          return chunk;
        });
    final digest = await sha256.bind(raw).single;
    if (count != trace['bytes'] || digest.toString() != trace['sha256']) {
      invalid();
    }
  }

  Future<Json> readRtc2(
    String account,
    ProvisionedIdentityRead read,
    String publicKey, {
    void Function(Json)? onDiagnostic,
  }) async {
    final result = await _execute(
      account,
      'rtc2-observe',
      read.inspectionParameters(publicKey),
      read.definition.runnerFiles,
      onDiagnostic,
    );
    if (result['outcome'] == 'interrupted') return result;
    final rows = result['observations'];
    if (rows is! List || rows.length < 6 || rows.any((row) => row is! Json)) {
      throw const ProvisioningFailure('Incomplete RTC2 observations.');
    }
    final before = rows[1]['before_proof'],
        after = rows[rows.length - 2]['after_proof'];
    final summary = rows.last['result'];
    if (summary is! Json ||
        summary['outcome'] != 'observed' ||
        summary['mode'] != 'quick' ||
        summary['definition'] != 'c83-rtc2-observation.v2' ||
        summary['wait_path_observed'] != true ||
        summary['role'] != read.build.role ||
        summary['source'] != read.build.source ||
        summary['artifact'] != read.build.artifact ||
        before is! Json ||
        after is! Json) {
      throw const ProvisioningFailure(
        'RTC2 result differs from the selected test or build.',
      );
    }
    for (final proof in [before, after]) {
      read.checkRegistryIdentity(proof);
      if (proof['role'] != read.build.role ||
          proof['build'] != read.build.source ||
          proof['hardware'] != read.device.hardwareUid ||
          proof['public_key'] != publicKey ||
          !hexId(proof['boot'] as String? ?? '', 32) ||
          !hexId(proof['signature'] as String? ?? '', 128) ||
          !hexId(proof['challenge'] as String? ?? '', 64)) {
        throw const ProvisioningFailure(
          'RTC2 identity proof differs from the selected device.',
        );
      }
    }
    if (after['boot'] != before['boot'] ||
        before['challenge'] == after['challenge']) {
      throw const ProvisioningFailure(
        'RTC2 proofs require fresh challenges on one boot.',
      );
    }
    final samples = rows.sublist(2, rows.length - 2);
    Json? first, last;
    var idleRequested = false;
    for (final row in samples) {
      final frame = row['frame'];
      if (!{'rtc2-sample', 'rtc2-idle'}.contains(row['command']) ||
          frame is! Json ||
          frame['type'] != 'rtc2_observation' ||
          frame['role'] != read.build.role ||
          frame['build'] != read.build.source ||
          frame['boot'] != before['boot'] ||
          frame['hardware'] != read.device.hardwareUid ||
          !{1, 2}.contains(frame['state']) ||
          (last != null && frame['state'] != 2)) {
        throw const ProvisioningFailure(
          'RTC2 sample differs from the proven device and boot.',
        );
      }
      if (row['command'] == 'rtc2-idle') idleRequested = true;
      if (frame['state'] == 2) {
        first ??= row as Json;
        last = row as Json;
      }
    }
    final rate = summary['host_relative_rate_error_ppb'];
    if (!idleRequested ||
        first == null ||
        last == null ||
        rate is! List ||
        rate.length != 2 ||
        rate.any((v) => v is! int) ||
        (rate.first as int) > (rate.last as int) ||
        summary['full_temperature_rate_bound'] != 'unqualified' ||
        first['ticks'] is! int ||
        last['ticks'] is! int ||
        last['ticks'] <= first['ticks'] ||
        first['before_ns'] is! int ||
        last['after_ns'] is! int ||
        last['after_ns'] - first['before_ns'] < 5000000000 ||
        first['frame']['waits'] is! int ||
        last['frame']['waits'] is! int ||
        last['frame']['waits'] <= first['frame']['waits'] ||
        last['frame']['longest_wait_ticks'] is! int ||
        last['frame']['longest_wait_ticks'] <= 0) {
      throw const ProvisioningFailure(
        'RTC2 measurement evidence is incomplete.',
      );
    }
    return {
      'outcome': 'passed',
      'before_proof': before,
      'after_proof': after,
      'frame': summary,
      ...result,
    };
  }

  Future<Json> readCryptoProbe(
    String account,
    ProvisionedIdentityRead read,
    String publicKey, {
    void Function(Json)? onDiagnostic,
  }) async {
    final reentry = read.definition.guide['key'] == 'c83-crypto-reentry-device';
    final keys = read.definition.guide['key'] == 'c83-crypto-keys-device';
    final result = await _execute(
      account,
      keys
          ? 'crypto-keys'
          : reentry
          ? 'crypto-reentry'
          : 'crypto-probe',
      read.inspectionParameters(publicKey),
      read.definition.runnerFiles,
      onDiagnostic,
    );
    if (!{'passed', 'failed', 'interrupted'}.contains(result['outcome'])) {
      throw const ProvisioningFailure('Invalid crypto probe result.');
    }
    if (result['outcome'] != 'passed') return result;
    final before = result['before_proof'], after = result['after_proof'];
    final frame = result['frame'];
    if (before is! Json || after is! Json || frame is! Json) {
      throw const ProvisioningFailure('Crypto probe evidence is incomplete.');
    }
    for (final proof in [before, after]) {
      read.checkRegistryIdentity(proof);
      if (proof['role'] != read.build.role ||
          proof['build'] != read.build.source ||
          proof['hardware'] != read.device.hardwareUid ||
          proof['public_key'] != publicKey ||
          proof['boot'] is! String ||
          !hexId(proof['boot'] as String, 32) ||
          proof['boot'] == '0' * 32 ||
          proof['challenge'] is! String ||
          !hexId(proof['challenge'] as String, 64) ||
          proof['signature'] is! String ||
          !hexId(proof['signature'] as String, 128)) {
        throw const ProvisioningFailure(
          'Crypto probe identity proof does not match.',
        );
      }
    }
    if (before['boot'] != after['boot'] ||
        before['challenge'] == after['challenge'] ||
        frame['v'] != 1 ||
        frame['ok'] != true ||
        frame['type'] !=
            (keys
                ? 'crypto_keys'
                : reentry
                ? 'crypto_reentry'
                : 'crypto_probe') ||
        frame['role'] != read.build.role ||
        frame['build'] != read.build.source ||
        frame['hardware'] != read.device.hardwareUid ||
        frame['boot'] != before['boot'] ||
        frame['state'] != 'passed' ||
        frame['cancel_requested'] != false ||
        frame['id'] is! int ||
        (frame['id'] as int) <= 0 ||
        (frame['id'] as int) > 0xffffffff ||
        frame['run_id'] is! int ||
        (frame['run_id'] as int) <= 0 ||
        (frame['run_id'] as int) > 0xffffffff ||
        (keys &&
            (frame.length != 17 ||
                !frame.keys.toSet().containsAll({
                  'v',
                  'id',
                  'ok',
                  'type',
                  'role',
                  'build',
                  'hardware',
                  'boot',
                  'run_id',
                  'state',
                  'cancel_requested',
                  'identity_signature',
                  'agreement',
                  'exhaustion',
                  'stale_rejected',
                  'cleaned',
                  'stack_free_words',
                }))) ||
        (keys
            ? [
                'identity_signature',
                'agreement',
                'exhaustion',
                'stale_rejected',
                'cleaned',
              ].any((name) => frame[name] != true)
            : reentry
            ? [
                'nested_refused',
                'outer_failed',
                'output_cleared',
                'input_intact',
                'later_hash',
              ].any((name) => frame[name] != true)
            : [
                'hash',
                'signature',
                'agreement',
                'random',
              ].any((name) => frame[name] != true)) ||
        frame['stack_free_words'] is! int ||
        (frame['stack_free_words'] as int) < 0 ||
        (frame['stack_free_words'] as int) > 0xffffffff ||
        (frame['elapsed_ms'] != null &&
            (frame['elapsed_ms'] is! int ||
                (frame['elapsed_ms'] as int) < 0 ||
                (frame['elapsed_ms'] as int) > 0xffffffff)) ||
        result['host_elapsed_ms'] is! int ||
        (result['host_elapsed_ms'] as int) < 0) {
      throw const ProvisioningFailure('Crypto probe frame does not match.');
    }
    return result;
  }

  Future<Json> readBenchReadiness(
    String account,
    ProvisionedIdentityRead read,
    String publicKey, {
    void Function(Json)? onDiagnostic,
  }) async {
    final result = await _execute(
      account,
      'credential-readiness',
      read.inspectionParameters(publicKey),
      read.definition.runnerFiles,
      onDiagnostic,
    );
    final inspection = result['inspection'];
    if (inspection is! Json) {
      throw const ProvisioningFailure('Readiness inspection is unavailable.');
    }
    _checkInspection(read, publicKey, inspection);
    final proof = inspection['identity_proof'];
    if (result['v'] != 1 ||
        result['ok'] != true ||
        result['id'] is! int ||
        (result['id'] as int) <= 0 ||
        result['type'] != 'credential_readiness' ||
        result['role'] != read.build.role ||
        result['build'] != read.build.source ||
        result['hardware'] != read.device.hardwareUid ||
        result['boot'] != inspection['boot'] ||
        proof is! Json ||
        jsonEncode(result['identity_proof']) != jsonEncode(proof) ||
        !{'empty', 'ready', 'pending'}.contains(result['state']) ||
        result['revision'] is! int ||
        (result['revision'] as int) < 0 ||
        (result['revision'] as int) > 0xffffffff ||
        (result['state'] == 'ready' &&
            ((result['revision'] as int) == 0 ||
                result['content_id'] is! String ||
                !hexId(result['content_id'] as String, 64))) ||
        (result['state'] != 'ready' &&
            (result['revision'] != 0 || result['content_id'] != '')) ||
        (inspection['state'] == 'blank') != (result['state'] == 'empty')) {
      throw const ProvisioningFailure(
        'Credential readiness did not match the inspected device.',
      );
    }
    return result;
  }

  Future<Json> readBenchDelivery(
    String account,
    ProvisionedIdentityRead read,
    String publicKey,
    PublicFactoryCredential credential, {
    void Function(Json)? onDiagnostic,
  }) async {
    final encoded = credential.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
    final result = await _execute(
      account,
      'credential-delivery',
      {
        'selection': read.inspectionParameters(publicKey),
        'credential': encoded,
        'credential_sha256': credential.digest,
      },
      read.definition.runnerFiles,
      onDiagnostic,
    );
    return _checkDeliveryResult(result, read, publicKey, credential);
  }

  Json _checkDeliveryResult(
    Json result,
    ProvisionedIdentityRead read,
    String publicKey,
    PublicFactoryCredential credential,
  ) {
    final identity = result['identity_proof'], proof = result['delivery_proof'];
    if (result.length != 2 || identity is! Json || proof is! Json) {
      throw const ProvisioningFailure(
        'Credential verification result is invalid.',
      );
    }
    read.checkRegistryIdentity(identity);
    if (identity['v'] != 1 ||
        identity['ok'] != true ||
        identity['type'] != 'identity' ||
        identity['algorithm'] != 'P256-SHA256' ||
        identity['challenge'] is! String ||
        !hexId(identity['challenge'] as String, 64) ||
        identity['challenge'] == '0' * 64 ||
        identity['signature'] is! String ||
        !hexId(identity['signature'] as String, 128) ||
        identity['role'] != read.build.role ||
        identity['build'] != read.build.source ||
        identity['hardware'] != read.device.hardwareUid ||
        identity['public_key'] != publicKey ||
        identity['boot'] is! String ||
        !hexId(identity['boot'] as String, 32) ||
        identity['boot'] == '0' * 32 ||
        proof.length != 18 ||
        proof['v'] != 1 ||
        proof['ok'] != true ||
        proof['id'] is! int ||
        (proof['id'] as int) <= 0 ||
        proof['type'] != 'credential_delivery' ||
        proof['role'] != read.build.role ||
        proof['build'] != read.build.source ||
        proof['hardware'] != read.device.hardwareUid ||
        proof['boot'] != identity['boot'] ||
        proof['device_id'] != read.device.id ||
        proof['serial'] != read.device.serial ||
        proof['article_id'] != read.article.articleId ||
        proof['article_revision_id'] != read.article.id ||
        proof['envelope_sha256'] != credential.digest ||
        proof['transfer_id'] is! int ||
        (proof['transfer_id'] as int) <= 0 ||
        (proof['transfer_id'] as int) > 0xffffffff ||
        proof['credential_revision'] is! int ||
        (proof['credential_revision'] as int) <= 0 ||
        (proof['credential_revision'] as int) > 0xffffffff ||
        proof['challenge'] is! String ||
        !hexId(proof['challenge'] as String, 64) ||
        proof['challenge'] == '0' * 64 ||
        proof['challenge'] == identity['challenge'] ||
        proof['content_id'] is! String ||
        !hexId(proof['content_id'] as String, 64) ||
        proof['content_id'] == '0' * 64 ||
        proof['signature'] is! String ||
        !hexId(proof['signature'] as String, 128) ||
        proof['signature'] == '0' * 128) {
      throw const ProvisioningFailure(
        'Credential verification did not match the selected device.',
      );
    }
    return result;
  }

  Json _checkInstallationProof(
    Object? value,
    Json delivery,
    int fault, {
    required bool review,
  }) {
    if (value is! Json ||
        value.length != 24 ||
        value['v'] != 1 ||
        value['ok'] != true ||
        value['id'] is! int ||
        (value['id'] as int) <= 0 ||
        value['type'] != 'credential_installation' ||
        value['fault'] != fault ||
        value['slots_used'] is! int ||
        (value['slots_used'] as int) < 0 ||
        (value['slots_used'] as int) > 9 ||
        value['signature'] is! String ||
        !hexId(value['signature'] as String, 128) ||
        value['signature'] == '0' * 128 ||
        [
          'role',
          'build',
          'boot',
          'hardware',
          'device_id',
          'serial',
          'article_id',
          'article_revision_id',
          'transfer_id',
          'challenge',
          'credential_revision',
          'content_id',
          'envelope_sha256',
        ].any((key) => value[key] != delivery[key]) ||
        (review
            ? value['result'] != 'review' ||
                  !{
                    'empty',
                    'ready',
                    'pending',
                  }.contains(value['journal_state']) ||
                  (fault == 1 && value['journal_state'] != 'empty')
            : fault == 1
            ? value['result'] != 'interrupted' ||
                  value['journal_state'] != 'pending'
            : !{'installed', 'retry'}.contains(value['result']) ||
                  value['journal_state'] != 'ready' ||
                  value['journal_revision'] != value['credential_revision'] ||
                  value['journal_content_id'] != value['content_id'])) {
      throw const ProvisioningFailure(
        'Installation proof differs from the selected verified credential.',
      );
    }
    return value;
  }

  Future<Json> readBenchInstallation(
    String account,
    ProvisionedIdentityRead read,
    String publicKey,
    PublicFactoryCredential credential,
    String attemptId,
    int fault,
    Future<Json> Function(Json) confirm, {
    void Function(Json)? onDiagnostic,
  }) async {
    final encoded = credential.bytes
        .map((v) => v.toRadixString(16).padLeft(2, '0'))
        .join();
    Json? reviewed;
    final result = await _execute(
      account,
      'credential-installation',
      {
        'selection': read.inspectionParameters(publicKey),
        'credential': encoded,
        'credential_sha256': credential.digest,
        'attempt_id': attemptId,
        'fault': fault,
      },
      read.definition.runnerFiles,
      onDiagnostic,
      (review) async {
        if (review.length != 6 ||
            review['attempt_id'] != attemptId ||
            review['review_token'] is! String ||
            !hexId(review['review_token'] as String, 64) ||
            review['expires_ms'] is! int ||
            (review['expires_ms'] as int) <= 0 ||
            (review['expires_ms'] as int) > 25000) {
          throw const ProvisioningFailure(
            'Installation confirmation is invalid.',
          );
        }
        final delivered = _checkDeliveryResult(
          {
            'identity_proof': review['identity_proof'],
            'delivery_proof': review['delivery_proof'],
          },
          read,
          publicKey,
          credential,
        );
        _checkInstallationProof(
          review['review'],
          delivered['delivery_proof'] as Json,
          fault,
          review: true,
        );
        reviewed = jsonDecode(jsonEncode(review)) as Json;
        return confirm(review);
      },
    );
    if (result['cancelled'] == true) throw BenchCancelled();
    if (result.length != 7 ||
        result['cancelled'] != false ||
        result['passed'] != true ||
        result['attempt_id'] != attemptId ||
        jsonEncode(result['review']) != jsonEncode(reviewed?['review'])) {
      throw const ProvisioningFailure(
        'Installation did not return a verified result. Inspect before recovery.',
      );
    }
    final delivered = _checkDeliveryResult(
      {
        'identity_proof': result['identity_proof'],
        'delivery_proof': result['delivery_proof'],
      },
      read,
      publicKey,
      credential,
    );
    _checkInstallationProof(
      result['review'],
      delivered['delivery_proof'] as Json,
      fault,
      review: true,
    );
    _checkInstallationProof(
      result['installation_proof'],
      delivered['delivery_proof'] as Json,
      fault,
      review: false,
    );
    return result;
  }

  Future<Json> readBenchPreparation(
    String account,
    ProvisionedIdentityRead read,
    String publicKey,
    String attemptId,
    Future<Json> Function(Json) confirm, {
    void Function(Json)? onDiagnostic,
  }) async {
    Json? reviewed;
    final result = await _execute(
      account,
      'credential-preparation',
      {
        'selection': read.inspectionParameters(publicKey),
        'attempt_id': attemptId,
      },
      read.definition.runnerFiles,
      onDiagnostic,
      (review) async {
        if (review.length != 4 ||
            review['attempt_id'] != attemptId ||
            review['inspection'] is! Json ||
            !hexId(review['review_token'] as String? ?? '', 64) ||
            review['expires_ms'] != 25000) {
          throw const ProvisioningFailure(
            'Preparation confirmation is invalid.',
          );
        }
        _checkInspection(read, publicKey, review['inspection'] as Json);
        if (review['inspection']['state'] != 'unknown') {
          throw const ProvisioningFailure(
            'Preserve recognizable or interrupted credential records.',
          );
        }
        reviewed = jsonDecode(jsonEncode(review)) as Json;
        return confirm(review);
      },
    );
    if (result['cancelled'] == true) throw BenchCancelled();
    if (result.length != 5 ||
        result['passed'] != true ||
        result['cancelled'] != false ||
        result['attempt_id'] != attemptId ||
        result['preparation_result'] is! Json ||
        jsonEncode(result['inspection']) !=
            jsonEncode(reviewed?['inspection'])) {
      throw const ProvisioningFailure(
        'Preparation did not return a verified result. Inspect before recovery.',
      );
    }
    final prepared = result['preparation_result'] as Json;
    _checkInspection(read, publicKey, {
      ...prepared,
      'identity_proof': result['inspection']['identity_proof'],
    });
    if (prepared['state'] != 'blank' ||
        prepared['sha256'] !=
            sha256.convert(List<int>.filled(8192, 255)).toString()) {
      throw const ProvisioningFailure(
        'Prepared storage did not verify as blank.',
      );
    }
    return result;
  }

  Future<Json> proveUpdateIdentity(
    String account,
    Json selection,
    BenchDefinition definition,
  ) async {
    final result = await _execute(
      account,
      'update-proof',
      selection,
      definition.runnerFiles,
    );
    final proof = result['proof'];
    if (proof is! Json ||
        proof['state'] != 'ready' ||
        proof['busy'] != false ||
        proof['failed'] != false ||
        proof['role'] != selection['role'] ||
        proof['build'] != selection['source'] ||
        proof['hardware'] != selection['hardware'] ||
        proof['public_key'] != selection['public_key'] ||
        proof['device_id'] != selection['device_id'] ||
        proof['serial'] != selection['serial'] ||
        proof['article_id'] != selection['article_id'] ||
        proof['article_revision_id'] != selection['article_revision_id'] ||
        !hexId(proof['boot'] as String? ?? '', 32) ||
        !hexId(proof['challenge'] as String? ?? '', 64) ||
        !hexId(proof['signature'] as String? ?? '', 128)) {
      throw const ProvisioningFailure('Update identity proof does not match.');
    }
    return proof;
  }

  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) => _execute(account, command, parameters, const {});

  Future<Json> _execute(
    String account,
    String command,
    Json parameters,
    Map<String, String> runnerPins, [
    void Function(Json)? onDiagnostic,
    Future<Json> Function(Json)? confirmation,
  ]) async {
    final pairedCommand =
        command == 'connection-bench' || command == 'connection-recovery';
    if (_busy) throw StateError('A provisioning step is already running');
    if (!RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
            .hasMatch(account) ||
        !{
          'inventory',
          'install',
          'identity',
          'provision',
          'inspect-storage',
          'prepare-storage',
          'inspect-control-storage',
          'prepare-control-storage',
          'credential-inspection',
          'credential-readiness',
          'startup-diagnostics',
          'rtc2-observe',
          'connection-bench',
          'connection-recovery',
          'crypto-probe',
          'crypto-reentry',
          'crypto-keys',
          'credential-delivery',
          'credential-installation',
          'credential-preparation',
          'update-proof',
        }.contains(command)) {
      throw const FormatException('Invalid provisioning request');
    }
    final program = updateProofProgram;
    if (command == 'update-proof' &&
        (program == null ||
            sha256.convert(utf8.encode(program)).toString() !=
                'ee9e0ce34d7dea32bc961140917075f0000a87aae09e4e408790c4f2060982ba')) {
      throw const FormatException(
        'Update proof adapter differs from the reviewed version',
      );
    }
    final args = command == 'credential-preparation'
        ? [
            '-B',
            '$firmwareRoot/tools/credential_preparation.py',
            '--evidence-root',
            '${evidenceRoot.path}/$account/usb',
          ]
        : command == 'credential-installation'
        ? [
            '-B',
            '$firmwareRoot/tools/credential_installation.py',
            '--evidence-root',
            '${evidenceRoot.path}/$account/usb',
          ]
        : command == 'credential-delivery'
        ? ['-B', '$firmwareRoot/tools/credential_delivery.py']
        : pairedCommand
        ? [
            '-B',
            '$firmwareRoot/tools/${command == 'connection-recovery' ? 'connection_recovery.py' : 'connection_bench.py'}',
          ]
        : command == 'rtc2-observe'
        ? ['-B', '$firmwareRoot/tools/rtc2_observe.py', 'quick']
        : command == 'startup-diagnostics'
        ? ['-B', '$firmwareRoot/tools/startup_diagnostics.py']
        : command == 'crypto-probe'
        ? ['-B', '$firmwareRoot/tools/crypto_probe.py']
        : command == 'crypto-keys'
        ? ['-B', '$firmwareRoot/tools/crypto_probe.py', '--keys']
        : command == 'crypto-reentry'
        ? ['-B', '$firmwareRoot/tools/crypto_probe.py', '--reentry']
        : command == 'credential-readiness'
        ? ['-B', '$firmwareRoot/tools/credential_readiness.py']
        : command == 'credential-inspection'
        ? ['-B', '$firmwareRoot/tools/credential_inspection.py']
        : command == 'update-proof'
        ? ['-B', '-c', program!, firmwareRoot]
        : ['-B', '$firmwareRoot/tools/provision.py', command];
    String? input;
    if (pairedCommand ||
        command == 'rtc2-observe' ||
        command == 'startup-diagnostics' ||
        command == 'crypto-probe' ||
        command == 'crypto-reentry' ||
        command == 'crypto-keys' ||
        command == 'credential-inspection' ||
        command == 'credential-readiness' ||
        command == 'credential-delivery' ||
        command == 'credential-installation' ||
        command == 'credential-preparation' ||
        command == 'update-proof') {
      input = jsonEncode(parameters);
      if (utf8.encode(input).length > 8192) {
        throw const FormatException('Inspection input exceeds limit');
      }
    }
    if (command == 'install' || command == 'identity') {
      final hardware = parameters['hardware'] as String;
      if (!hexId(hardware, 16)) {
        throw const FormatException('Invalid physical USB identity');
      }
      args.addAll(['--hardware', hardware]);
      if (command == 'identity') {
        final source = parameters['source'] as String;
        if (!hexId(source, 64)) {
          throw const FormatException('Invalid firmware source');
        }
        args.addAll(['--source', source]);
        if (parameters.containsKey('role')) {
          final role = parameters['role'];
          if (!{'Link', 'Core'}.contains(role)) {
            throw const FormatException('Invalid product role');
          }
          args.addAll(['--role', role as String]);
        }
      } else {
        args.addAll([
          '--manifest',
          parameters['manifest'] as String,
          '--volume',
          parameters['volume'] as String,
        ]);
      }
    }
    final storage = {
      'inspect-storage',
      'prepare-storage',
      'inspect-control-storage',
      'prepare-control-storage',
    }.contains(command);
    if (command == 'provision' || storage) {
      // Only public server binding fields reach Python. Never send the session.
      input = jsonEncode({
        for (final key in [
          'request_id',
          'device_id',
          'serial',
          'article_id',
          'article_revision_id',
          'hardware',
          'source',
          'artifact',
          'challenge',
          'public_key',
          if (parameters.containsKey('role')) 'role',
          if (command.startsWith('prepare-')) 'inspection_token',
        ])
          key: parameters[key],
      });
      if (utf8.encode(input).length > 8192) {
        throw const FormatException('Provisioning input exceeds limit');
      }
    }
    if (storage) {
      args.addAll(['--manifest', parameters['manifest'] as String]);
      if (command.startsWith('prepare-') &&
          (parameters['inspection_token'] is! String ||
              !hexId(parameters['inspection_token'] as String, 64))) {
        throw const FormatException('Current storage confirmation required');
      }
    }
    if (command == 'install' || command == 'provision' || storage) {
      args.addAll(['--evidence-root', '${evidenceRoot.path}/$account/usb']);
    }
    if (pairedCommand &&
        (!runnerPins.containsKey('tools/connection_bench.py') ||
            (command == 'connection-recovery' &&
                !runnerPins.containsKey('tools/connection_recovery.py')))) {
      throw const BenchBlocked(
        'A pinned peer handshake procedure is required.',
      );
    }
    _busy = true;
    _cancelled = false;
    var acceptingConfirmation = true;
    try {
      try {
        await verifyContract();
        for (final pin in runnerPins.entries) {
          if (await _digest(File('$firmwareRoot/${pin.key}')) != pin.value) {
            throw const FormatException(
              'Identity procedure runner or contract revision differs',
            );
          }
        }
      } on Object catch (e) {
        if (runnerPins.isNotEmpty) {
          throw BenchBlocked('Pinned runner unavailable: $e');
        }
        rethrow;
      }
      if (_cancelled) throw BenchCancelled();
      final process = await _startProcess(
        '$firmwareRoot/build/bench-venv/bin/python',
        args,
      );
      _process = process;
      var ended = false;
      Object? confirmationError;
      final interactive = confirmation != null;
      var reviews = 0;
      var resultReceived = false;
      Object? eventError;
      if (_cancelled) process.kill();
      Future<List<int>> capture(Stream<List<int>> stream) async {
        final bytes = <int>[];
        await for (final chunk in stream) {
          if (bytes.length + chunk.length > (pairedCommand ? 262144 : 65536)) {
            process.kill();
            throw const FormatException('Runner output exceeds limit');
          }
          bytes.addAll(chunk);
        }
        return bytes;
      }

      Future<List<int>> captureInstallation() async {
        final bytes = <int>[], line = <int>[];
        await for (final chunk in process.stdout) {
          if (bytes.length + chunk.length > 65536) {
            eventError = const FormatException('Runner output exceeds limit');
            process.kill();
            break;
          }
          bytes.addAll(chunk);
          if (eventError != null) continue;
          try {
            for (final byte in chunk) {
              if (byte != 10) {
                line.add(byte);
                continue;
              }
              final frame = jsonDecode(utf8.decode(line));
              line.clear();
              if (frame is! Json ||
                  frame.length != 2 ||
                  frame['data'] is! Json) {
                throw const FormatException('Invalid installation event');
              }
              if (frame['event'] == 'review') {
                if (++reviews != 1 || resultReceived) {
                  throw const FormatException(
                    'Unexpected installation confirmation',
                  );
                }
                Future.sync(() => confirmation!(frame['data'] as Json))
                    .then((approval) async {
                      if (acceptingConfirmation && !_cancelled && !ended) {
                        process.stdin.writeln(jsonEncode(approval));
                        await process.stdin.flush();
                        await process.stdin.close();
                      }
                    })
                    .catchError((Object error) {
                      confirmationError = error;
                      process.kill();
                    });
              } else if (frame['event'] == 'result') {
                if (reviews != 1 || resultReceived) {
                  throw const FormatException('Unexpected installation result');
                }
                resultReceived = true;
              } else {
                throw const FormatException('Unknown installation event');
              }
            }
          } catch (error) {
            eventError = error;
            process.kill();
          }
        }
        if (line.isNotEmpty) {
          eventError ??= const FormatException('Incomplete installation event');
        }
        return bytes;
      }

      final outputs = Future.wait<Object>([
        interactive ? captureInstallation() : capture(process.stdout),
        capture(process.stderr),
        process.exitCode.then((code) {
          ended = true;
          return code;
        }),
      ]);
      Object? inputError;
      try {
        if (input != null && !ended) process.stdin.writeln(input);
        if (!interactive) {
          await process.stdin.close();
        } else {
          await process.stdin.flush();
        }
      } catch (error) {
        inputError = error;
      }
      var timedOut = false;
      final output = await outputs.timeout(
        pairedCommand ? const Duration(minutes: 5, seconds: 10) : timeout,
        onTimeout: () async {
          timedOut = true;
          acceptingConfirmation = false;
          process.kill(ProcessSignal.sigkill);
          return outputs;
        },
      );
      if (command != 'inventory') {
        final logs = await Directory(
          '${evidenceRoot.path}/$account/usb/adapter',
        ).create(recursive: true);
        final attempt = await logs.createTemp(
          'step-',
        ); // macOS mkdtemp: private mode 0700.
        final diagnostic = <String, dynamic>{
          'command': command,
          'exit_code': output[2],
          'stdout_base64': base64Encode(output[0] as List<int>),
          'stderr_base64': base64Encode(output[1] as List<int>),
        };
        onDiagnostic?.call(diagnostic);
        await File('${attempt.path}/result.json')
            .writeAsString(jsonEncode(diagnostic), flush: true);
      }
      if (_cancelled) throw BenchCancelled();
      if (timedOut) throw TimeoutException('USB action timed out.');
      if (eventError != null) throw eventError!;
      if (confirmationError != null) throw confirmationError!;
      if (output[2] != 0 || inputError != null) {
        if (command == 'identity' ||
            command == 'credential-inspection' ||
            command == 'credential-readiness' ||
            command == 'rtc2-observe' ||
            command == 'startup-diagnostics' ||
            command == 'crypto-probe' ||
            command == 'crypto-reentry' ||
            command == 'crypto-keys' ||
            command == 'credential-delivery' ||
            command == 'credential-installation' ||
            command == 'credential-preparation' ||
            command == 'update-proof') {
          final error = utf8.decode(
            output[1] as List<int>,
            allowMalformed: true,
          );
          if (runnerPins.isNotEmpty &&
              (error.contains(
                    'Connected device or firmware does not match selection',
                  ) ||
                  error.contains(
                    'Selected USB device is missing or ambiguous',
                  ))) {
            throw const BenchBlocked(
              'Connected target or firmware differs from selection',
            );
          }
          if (command == 'rtc2-observe') {
            final lines = const LineSplitter().convert(
              utf8.decode(output[0] as List<int>, allowMalformed: true),
            );
            final last = lines.isEmpty ? null : jsonDecode(lines.last);
            if (last case {
              'result': {
                'outcome': 'interrupted',
                'error': final String reason,
              },
            }) {
              return {'outcome': 'interrupted', 'error': reason};
            }
            throw const ProvisioningFailure(
              'RTC2 observation stopped before a result was available. Check the saved diagnostic.',
            );
          }
          throw ProvisioningFailure(
            interactive
                ? 'Installation stopped. Retain the diagnostic and inspect the selected device before any separately confirmed recovery.'
                : 'USB identity read failed. Check the saved diagnostic, selected board and expected build.',
          );
        }
        if (storage) {
          throw const ProvisioningFailure(
            'Storage preparation stopped. Keep this reservation and check the saved diagnostic, selected build and supported board profile. Leave the device in normal USB mode.',
          );
        }
        throw const ProvisioningFailure(
          'USB step failed. Keep this reservation, check the device and its firmware, then retry. For a new firmware install, put the device in USB bootloader mode and refresh.',
        );
      }
      final decoded = utf8.decode(output[0] as List<int>);
      if (command == 'rtc2-observe' || pairedCommand) {
        return {
          'observations': [
            for (final line in const LineSplitter().convert(decoded))
              jsonDecode(line),
          ],
        };
      }
      final events = interactive
          ? const LineSplitter().convert(decoded)
          : <String>[];
      if (interactive && (reviews != 1 || events.length != 2)) {
        throw const FormatException('Installation events are incomplete');
      }
      final result = interactive
          ? (jsonDecode(events.last) as Json)['data']
          : jsonDecode(decoded);
      if (result is! Json) {
        throw const FormatException('Invalid provisioning report');
      }
      return result;
    } finally {
      acceptingConfirmation = false;
      _process = null;
      _busy = false;
    }
  }

  @override
  Future<void> cancel() async {
    _cancelled = true;
    final process = _process;
    if (process == null) return;
    process.kill();
    await process.exitCode.timeout(
      const Duration(seconds: 2),
      onTimeout: () {
        process.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
  }
}
