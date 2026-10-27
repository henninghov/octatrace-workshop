import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/registry.dart';
import '../domain/ports.dart';

/// Private operator-scoped evidence and reservation retry identities.
/// Cloud failure and logout leave files intact. No passwords/tokens are stored.
final class EvidenceJournal implements EvidenceStore {
  EvidenceJournal(this.root);
  final Directory root;
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
}
