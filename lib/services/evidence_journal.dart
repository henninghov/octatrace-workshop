import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/registry.dart';
import '../domain/ports.dart';
import '../domain/bench_session.dart';
import '../domain/claimed_update.dart';
import 'bench_files.dart';

/// Private operator-scoped evidence and reservation retry identities.
/// Cloud failure and logout leave files intact. No passwords/tokens are stored.
final class EvidenceJournal
    implements EvidenceStore, BenchStore, ClaimedUpdateStore {
  EvidenceJournal(
    this.root, {
    Directory? updateLocks,
    Future<bool> Function()? flushUpdateIntent,
  }) : updateLocks = updateLocks ?? Directory('${root.path}/update-locks'),
       flushUpdateIntent = flushUpdateIntent ?? _flushUpdateIntent;
  final Directory root;
  final Directory updateLocks;
  final Future<bool> Function() flushUpdateIntent;
  static Future<bool> _flushUpdateIntent() async =>
      (await Process.run('/bin/sync', const <String>[])).exitCode == 0;
  Future<Directory> _account(String account) async {
    if (!RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
        .hasMatch(account)) {
      throw const FormatException('Operator UUID required for local evidence');
    }
    await root.create(recursive: true);
    final permission = await Process.run('/bin/chmod', ['700', root.path]);
    if (permission.exitCode != 0) {
      throw const FileSystemException('Cannot protect evidence folder');
    }
    return Directory('${root.path}/$account')..createSync(recursive: true);
  }

  String _key(String parameters) =>
      sha256.convert(utf8.encode(parameters)).toString();

  @override
  Future<String> reservation(
    String account,
    String parameters,
    String Function() createId,
  ) async {
    final dir = await _account(account);
    final file = File('${dir.path}/reservation-${_key(parameters)}.json');
    // Append mode avoids truncation before the exclusive lock is acquired.
    final handle = await file.open(mode: FileMode.append);
    try {
      await handle.lock(FileLock.exclusive);
      if (await handle.length() != 0) {
        final saved = jsonDecode(await file.readAsString()) as Json;
        if (saved['parameters'] != parameters) {
          throw const FormatException('Conflicting local reservation');
        }
        return saved['id'] as String;
      }
      final id = createId();
      await handle.writeString(
        jsonEncode({'id': id, 'parameters': parameters}),
      );
      await handle.flush();
      return id;
    } finally {
      await handle.close();
    }
  }

  @override
  Future<void> acknowledgeReservation(
    String account,
    String parameters,
    String expectedId,
  ) async {
    final dir = await _account(account);
    final file = File('${dir.path}/reservation-${_key(parameters)}.json');
    if (await file.exists()) {
      final saved = jsonDecode(await file.readAsString()) as Json;
      if (saved['id'] == expectedId) await file.delete();
    }
  }

  @override
  Future<void> save(String account, Json record) async {
    final dir = await _account(account);
    final pending = Directory('${dir.path}/pending');
    await pending.create(recursive: true);
    final id = record['id'] as String;
    if (!RegExp(r'^[0-9a-f-]{36}$').hasMatch(id)) {
      throw const FormatException('Evidence UUID required');
    }
    final file = File('${pending.path}/$id.json');
    final encoded = jsonEncode(record);
    if (await file.exists()) {
      if (await file.readAsString() != encoded) {
        throw const FormatException('Evidence identity conflict');
      }
      return;
    }
    final temp = File('${file.path}.tmp');
    await temp.writeAsString(encoded, flush: true);
    await temp.rename(file.path);
  }

  Future<File> _controlReceipt(String account, Json record) async {
    final dir = await _account(account);
    final receipts = Directory('${dir.path}/factory-storage-confirmations-v1');
    await receipts.create(recursive: true);
    return File('${receipts.path}/${_key(jsonEncode(record))}.json');
  }

  @override
  Future<void> confirmControlStorage(String account, Json record) async {
    final file = await _controlReceipt(account, record);
    if (await file.exists()) {
      if (await file.readAsString() != jsonEncode(record)) {
        throw const FormatException('Control inspection receipt conflict');
      }
      return;
    }
    final temp = File('${file.path}.tmp');
    await temp.writeAsString(jsonEncode(record), flush: true);
    await temp.rename(file.path);
  }

  @override
  Future<bool> controlStorageConfirmed(String account, Json record) async {
    final file = await _controlReceipt(account, record);
    return await file.exists() &&
        await file.readAsString() == jsonEncode(record);
  }

  @override
  Future<List<Json>> pending(String account) async {
    final dir = await _account(account);
    final pending = Directory('${dir.path}/pending');
    if (!await pending.exists()) return [];
    final result = <Json>[];
    await for (final file in pending.list()) {
      if (file is File && file.path.endsWith('.tmp')) {
        throw const FormatException(
          'Interrupted local evidence write requires review',
        );
      }
      if (file is File && file.path.endsWith('.json')) {
        result.add(jsonDecode(await file.readAsString()) as Json);
      }
    }
    return result;
  }

  @override
  Future<void> synced(String account, String id) async {
    final dir = await _account(account);
    final synced = Directory('${dir.path}/synced');
    await synced.create(recursive: true);
    await File('${dir.path}/pending/$id.json')
        .rename('${synced.path}/$id.json');
  }

  Future<File> _updateLock(Json record) async {
    final hardware = record['hardware'];
    if (hardware is! String || !RegExp(r'^[0-9a-f]{16}$').hasMatch(hardware)) {
      throw const FormatException('Invalid update hardware');
    }
    await updateLocks.create(recursive: true);
    return File('${updateLocks.path}/${_key(hardware)}.json');
  }

  Future<Directory> _updateAttempt(Json record) async {
    final account = record['account'];
    final id = record['id'];
    if (account is! String ||
        id is! String ||
        !RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$').hasMatch(id)) {
      throw const FormatException('Invalid update attempt identity');
    }
    return Directory('${(await _account(account)).path}/firmware-updates/$id');
  }

  @override
  Future<Json?> pendingUpdate(String account, String hardware) async {
    await _account(account);
    final lock = await _updateLock({'hardware': hardware});
    if (!await lock.exists()) return null;
    final binding = jsonDecode(await lock.readAsString()) as Json;
    if (binding['account'] != account ||
        binding['hardware'] != hardware ||
        binding['id'] is! String) {
      throw const FormatException('A prior device update requires review');
    }
    final dir = await _updateAttempt(binding);
    if (!await dir.exists()) {
      throw const FormatException('Prior update evidence requires review');
    }
    final records = <int>[];
    await for (final entry in dir.list(followLinks: false)) {
      if (entry is File &&
          RegExp(r'^[0-9]+\.json$').hasMatch(entry.uri.pathSegments.last)) {
        records.add(int.parse(entry.uri.pathSegments.last.split('.').first));
      }
    }
    records.sort();
    if (records.isEmpty ||
        records.first != 1 ||
        records.last != records.length) {
      throw const FormatException('Prior update evidence is incomplete');
    }
    Json? latest;
    for (final number in records) {
      final envelope = jsonDecode(
        await File('${dir.path}/$number.json').readAsString(),
      ) as Json;
      final record = envelope['record'] as Json;
      if (envelope['sha256'] != benchHash(jsonEncode(record)) ||
          record['generation'] != number ||
          record['account'] != account ||
          record['id'] != binding['id'] ||
          record['hardware'] != hardware) {
        throw const FormatException('Prior update evidence differs');
      }
      latest = record;
    }
    return latest;
  }

  @override
  Future<void> beginUpdate(Json record) async {
    if (record['generation'] != 1 || record['phase'] != 'preflight') {
      throw const FormatException('Invalid update start');
    }
    await _account(record['account'] as String);
    final lock = await _updateLock(record);
    // Atomic exclusive publication prevents concurrent starts for this hardware,
    // including from another operator or another Workshop process.
    await publishBenchFile(
      lock,
      jsonEncode({
        'id': record['id'],
        'account': record['account'],
        'hardware': record['hardware'],
      }),
    );
    await saveUpdate(record);
  }

  @override
  Future<void> saveUpdate(Json record) async {
    final lock = await _updateLock(record);
    final expected = {
      'id': record['id'],
      'account': record['account'],
      'hardware': record['hardware'],
    };
    if (!await lock.exists() ||
        await lock.readAsString() != jsonEncode(expected)) {
      throw const FormatException('Update attempt is not exclusively held');
    }
    final dir = await _updateAttempt(record);
    await dir.create(recursive: true);
    final generation = record['generation'];
    if (generation is! int ||
        generation < 1 ||
        (generation > 1 &&
            !await File('${dir.path}/${generation - 1}.json').exists())) {
      throw const FormatException('Update attempt generation is missing');
    }
    if (generation > 1) {
      final previousEnvelope = jsonDecode(
        await File('${dir.path}/${generation - 1}.json').readAsString(),
      ) as Json;
      final previous = previousEnvelope['record'] as Json;
      if (previousEnvelope['sha256'] != benchHash(jsonEncode(previous)) ||
          previous['generation'] != generation - 1 ||
          [
            'id',
            'account',
            'device_id',
            'hardware',
            'owner_id',
            'serial',
            'role',
            'operator_ready_confirmation',
            'before_source',
            'after_source',
            'after_artifact',
            'guide_snapshot',
            'guide_sha256',
            'proof_runner_sha256',
            'owner_dependency_guide_sha256',
            'workshop_sha256',
            'started_at',
          ].any((key) => previous[key] != record[key]) ||
          (previous.containsKey('before_proof') &&
              jsonEncode(previous['before_proof']) !=
                  jsonEncode(record['before_proof'])) ||
          (previous.containsKey('installation') &&
              jsonEncode(previous['installation']) !=
                  jsonEncode(record['installation']))) {
        throw const FormatException('Update history or binding changed');
      }
      const transitions = {
        'preflight': {'awaiting_bootloader', 'preflight_failed'},
        'awaiting_bootloader': {'write_started', 'cancelled_before_write'},
        'write_started': {'awaiting_postflight', 'interrupted_after_write'},
        'awaiting_postflight': {'verified', 'interrupted_after_write'},
      };
      if (!(transitions[previous['phase']]?.contains(record['phase']) ??
          false)) {
        throw const FormatException('Invalid update phase transition');
      }
    }
    final file = File('${dir.path}/$generation.json');
    final payload = jsonEncode(record);
    final envelope = jsonEncode({
      'sha256': benchHash(payload),
      'record': record,
    });
    if (await file.exists()) {
      if (await file.readAsString() != envelope) {
        throw const FormatException('Update attempt generation changed');
      }
    } else {
      await publishBenchFile(file, envelope);
    }
    if (record['phase'] == 'write_started' && !await flushUpdateIntent()) {
      // No device write may follow a failed flush, even on exact replay.
      throw const FileSystemException('Cannot flush update intent');
    }
  }

  @override
  Future<void> releaseUpdate(Json record) async {
    if (!{
      'verified',
      'cancelled_before_write',
      'preflight_failed',
    }.contains(record['phase'])) {
      throw const FormatException('Interrupted update requires review');
    }
    final dir = await _updateAttempt(record);
    final generation = record['generation'];
    final file = File('${dir.path}/$generation.json');
    final payload = jsonEncode(record);
    if (!await file.exists() ||
        await file.readAsString() !=
            jsonEncode({'sha256': benchHash(payload), 'record': record})) {
      throw const FormatException('Update outcome is not durable');
    }
    final lock = await _updateLock(record);
    final expected = {
      'id': record['id'],
      'account': record['account'],
      'hardware': record['hardware'],
    };
    if (!await lock.exists() ||
        await lock.readAsString() != jsonEncode(expected)) {
      throw const FormatException('Update lock changed');
    }
    await lock.delete();
  }

  @override
  Future<String> exportUpdate(Json record, String folder) async {
    final dir = await _updateAttempt(record);
    final generation = record['generation'];
    final saved = File('${dir.path}/$generation.json');
    final payload = jsonEncode(record);
    final envelope = jsonEncode({
      'sha256': benchHash(payload),
      'record': record,
    });
    if (!await saved.exists() || await saved.readAsString() != envelope) {
      throw const FormatException('Update report is not durably saved');
    }
    final destination = Directory(folder);
    if (!destination.isAbsolute || !await destination.exists()) {
      throw const FileSystemException(
        'Choose an existing absolute export folder',
      );
    }
    final digest = benchHash(envelope);
    final file = File(
      '${destination.path}/octatrace-update-${record['id']}-$digest.json',
    );
    if (await file.exists()) {
      if (await file.readAsString() != envelope) {
        throw const FormatException('Existing export differs');
      }
    } else {
      await publishBenchFile(file, envelope);
    }
    return file.path;
  }

  Future<Directory> _benchDirectory(String account) async =>
      Directory('${(await _account(account)).path}/bench')
        ..createSync(recursive: true);

  Future<Directory> _attempt(String account, String id) async {
    if (!RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$').hasMatch(id)) {
      throw const FormatException('Invalid bench attempt ID');
    }
    return Directory('${(await _benchDirectory(account)).path}/$id');
  }

  @override
  Future<void> saveBench(Json report) async {
    final dir = await _attempt(report['operator'], report['id']);
    await dir.create(recursive: true);
    final gen = report['generation'] as int;
    final file = File('${dir.path}/$gen.json');
    final bytes = benchEnvelope(report);
    if (await file.exists() && await file.readAsString() == bytes) return;
    if (gen < 1 ||
        (gen > 1 && !await File('${dir.path}/${gen - 1}.json').exists())) {
      throw const FormatException('Missing bench generation');
    }
    await publishBenchFile(file, bytes);
  }

  @override
  Future<Json> reopenBench(String account, String id) async {
    final dir = await _attempt(account, id);
    final records = <int>[];
    await for (final entry in dir.list(followLinks: false)) {
      if (entry is File && entry.path.endsWith('.json')) {
        records.add(int.parse(entry.uri.pathSegments.last.split('.').first));
      }
    }
    records.sort();
    if (records.isEmpty ||
        records.first != 1 ||
        records.last != records.length) {
      throw const FormatException('Incomplete bench journal');
    }
    final report = readBenchEnvelope(
      await File('${dir.path}/${records.last}.json').readAsString(),
      account,
      id,
    );
    if (report['generation'] != records.last) {
      throw const FormatException('Incorrect bench generation');
    }
    return report;
  }

  @override
  Future<List<Json>> benchHistory(String account) async {
    final reports = <Json>[];
    await for (final dir in (await _benchDirectory(
      account,
    )).list(followLinks: false)) {
      if (dir is Directory) {
        final id = dir.path.split('/').last;
        // A crash before the first atomic publication has no started attempt.
        if (await dir
            .list(followLinks: false)
            .any((e) => e is File && e.path.endsWith('.json'))) {
          reports.add(await reopenBench(account, id));
        }
      }
    }
    reports.sort(
      (a, b) => (b['started_at'] as String).compareTo(a['started_at']),
    );
    return reports;
  }

  Future<File> _benchReceipt(Json report) async {
    final dir = await _attempt(report['operator'], report['id']);
    return File('${dir.path}/${report['generation']}.verified');
  }

  Future<bool> benchVerified(Json report) async {
    final file = await _benchReceipt(report);
    return await file.exists() &&
        await file.readAsString() == benchHash(jsonEncode(report));
  }

  Future<void> markBenchVerified(Json report) async {
    final file = await _benchReceipt(report);
    try {
      await publishBenchFile(file, benchHash(jsonEncode(report)));
    } on FileSystemException {
      if (!await benchVerified(report)) rethrow;
    }
  }

  @override
  Future<({String path, String digest, int bytes})> exportBench(
    Json report,
    String folder,
  ) async {
    final dir = Directory(folder);
    if (!dir.isAbsolute || !await dir.exists()) {
      throw const FileSystemException(
        'Choose an existing absolute export folder',
      );
    }
    final bytes = benchEnvelope(report);
    final digest = benchHash(bytes);
    final file = File('${dir.path}/octatrace-${report['id']}-$digest.json');
    if (!await file.exists()) await publishBenchFile(file, bytes);
    if (await file.readAsString() != bytes) {
      throw const FormatException('Export readback differs');
    }
    return (path: file.path, digest: digest, bytes: utf8.encode(bytes).length);
  }
}
