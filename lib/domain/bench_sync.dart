import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'bench_session.dart';
import 'registry.dart';

typedef BenchRpc = Future<dynamic> Function(
  String account,
  String name,
  Json parameters,
);

/// All uploads start from a reopened local generation. Server acknowledgements
/// live beside the journal; they never change the captured result or its digest.
final class BenchSync {
  BenchSync(this.call, this.hasReceipt, this.saveReceipt);
  final BenchRpc call;
  final Future<bool> Function(Json report) hasReceipt;
  final Future<void> Function(Json report) saveReceipt;

  Future<void> upload(
    String account,
    String id,
    BenchStore store,
    bool Function() current,
  ) async {
    void check() {
      if (!current()) throw SessionExpired();
    }

    Future<dynamic> rpc(String name, Json params) async {
      check();
      final value = await call(account, name, params);
      check();
      return value;
    }

    final chain = <Json>[];
    final visited = <String>{};
    String? attempt = id;
    while (attempt != null) {
      check();
      if (!visited.add(attempt)) {
        throw const FormatException('Cyclic retry history');
      }
      final r = await store.reopenBench(account, attempt);
      if (r['id'] != attempt || r['operator'] != account) {
        throw const FormatException('Local attempt differs');
      }
      if (await hasReceipt(r)) break;
      chain.add(r);
      attempt = r['prior_attempt'];
    }
    if (chain.isEmpty) return;
    final catalog = await rpc('workshop_test_definitions', {}) as List;
    for (final r in chain.reversed) {
      if (!catalog.any(
        (d) =>
            d['test_key'] == r['definition_key'] &&
            d['revision'] == r['definition_revision'] &&
            d['definition_sha256'] == r['definition_sha256'] &&
            d['snapshot'] == r['definition_snapshot'],
      )) {
        throw const FormatException('Reviewed test definition unavailable');
      }
      final refs = <Json>[];
      final content = <String, String>{};
      for (final a in r['artifacts']) {
        final raw = a['content'] as String;
        if (a['run_id'] != r['id'] ||
            benchHash(raw) != a['sha256'] ||
            utf8.encode(raw).length != a['bytes']) {
          throw const FormatException('Local artifact differs');
        }
        refs.add({
          for (final key in ['step', 'type', 'bytes', 'sha256']) key: a[key],
        });
        content[a['sha256']] = base64Encode(utf8.encode(raw));
      }
      final generation = r['generation'] as int;
      final header = <String, dynamic>{
        for (final k in [
          'id',
          'operator',
          'prior_attempt',
          'started_at',
          'definition_key',
          'definition_revision',
          'definition_sha256',
          'workshop_sha256',
        ])
          k: r[k],
        'participants': [
          {'device_id': r['device']['id'], 'firmware': r['firmware']},
        ],
      };
      final result = <String, dynamic>{
        for (final k in ['generation', 'outcome', 'ended_at', 'steps']) k: r[k],
        'artifacts': refs,
        if (r['outcome'] == 'Passed')
          'export_receipt': {
            for (final k in ['bytes', 'sha256']) k: r['exports'].last[k],
          },
      };
      if (await rpc('workshop_submit_test_run', {
            'p_header': header,
            'p_result': result,
          }) !=
          generation) {
        throw const FormatException('Run acknowledgement differs');
      }
      final run = {'p_run': r['id'], 'p_generation': generation};
      final items = await rpc('workshop_test_artifacts', run) as List;
      if (items.length != refs.length) {
        throw const FormatException('Server manifest count differs');
      }
      for (var i = 0; i < refs.length; i++) {
        final a = refs[i], item = items[i];
        if (!a.keys.every((k) => a[k] == item[k]) ||
            item['verified'] is! bool) {
          throw const FormatException('Server manifest differs');
        }
        final hash = a['sha256'] as String;
        final bytes = content[hash]!;
        final request = {...run, 'p_sha256': hash};
        if (!item['verified'] &&
            await rpc('workshop_put_test_artifact', {
                  ...request,
                  'p_base64': bytes,
                }) !=
                hash) {
          throw const FormatException('Artifact acknowledgement differs');
        }
        if (await rpc('workshop_read_test_artifact', request) != bytes) {
          throw const FormatException('Stored artifact readback differs');
        }
      }
      check();
      await saveReceipt(r);
    }
  }

  /// Recheck the actual hosted bytes before displaying a shared attachment.
  Future<String> readArtifact(
    String account,
    Json row,
    Json artifact,
    bool Function() current,
  ) async {
    if (!current() || row['header']['operator'] != account) {
      throw SessionExpired();
    }
    final encoded = await call(account, 'workshop_read_test_artifact', {
      'p_run': row['header']['id'],
      'p_generation': row['result']['generation'],
      'p_sha256': artifact['sha256'],
    }) as String;
    if (!current()) throw SessionExpired();
    final bytes = base64Decode(encoded);
    if (bytes.length != artifact['bytes'] ||
        sha256.convert(bytes).toString() != artifact['sha256']) {
      throw const FormatException('Shared artifact checksum differs');
    }
    return artifact['type'] == 'application/json'
        ? utf8.decode(bytes)
        : "${bytes.length} verified bytes · ${artifact['sha256']}";
  }

  Future<List<Json>> history(String account, bool Function() current) async {
    final runs = <Json>[];
    String? after;
    const limit = 20;
    while (current()) {
      final page = await call(account, 'workshop_test_runs', {
        'p_after': after,
        'p_limit': limit,
      }) as List;
      if (!current()) break;
      for (final value in page) {
        final header = value['header'];
        final id = header['id'] as String;
        if (header['operator'] != account ||
            (after != null && id.compareTo(after) <= 0)) {
          throw const FormatException('Shared history binding differs');
        }
        runs.add(Map<String, dynamic>.from(value));
        after = id;
      }
      if (page.length < limit) return runs;
    }
    throw SessionExpired();
  }
}
