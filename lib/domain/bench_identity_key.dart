import 'package:crypto/crypto.dart';

import 'registry.dart';

final class IdentityKeyLookup {
  const IdentityKeyLookup(this.gateway);
  final WorkshopGateway gateway;

  Future<String> find(DeviceRecord device, ArticleRevision article) async =>
      provisionedKey(await gateway.load(), device, article);
}

/// Recover the provisioned key only from the operator-authorized registry's
/// server-verified provisioning event, never from a fresh USB response.
String provisionedKey(
  Registry registry,
  DeviceRecord device,
  ArticleRevision article,
) {
  final current = registry.devices
      .where((value) => value.id == device.id)
      .toList();
  if (current.length != 1 ||
      current.single.state != 'provisioned' ||
      current.single.serial != device.serial ||
      current.single.revisionId != article.id ||
      current.single.hardwareUid != device.hardwareUid ||
      current.single.ownerId != device.ownerId) {
    throw const FormatException('Selected registry identity changed');
  }
  final candidates = <String>{};
  for (final event in registry.runs) {
    if (event['event_type'] != 'provisioned' ||
        event['device_id'] != device.id) {
      continue;
    }
    final report = event['report'];
    if (report is! Map || report['algorithm'] != 'P256-SHA256') continue;
    final verification = report['verification'];
    if (verification is! Map) continue;
    final before = verification['before'], after = verification['after'];
    if (before is! Map || after is! Map) continue;
    final key = before['public_key'];
    final bootBefore = before['boot'], bootAfter = after['boot'];
    if (key is! String ||
        !RegExp(r'^04[0-9a-f]{128}$').hasMatch(key) ||
        after['public_key'] != key ||
        bootBefore is! String ||
        bootAfter is! String ||
        !RegExp(r'^[0-9a-f]{32}$').hasMatch(bootBefore) ||
        !RegExp(r'^[0-9a-f]{32}$').hasMatch(bootAfter) ||
        bootBefore == '0' * 32 ||
        bootAfter == '0' * 32 ||
        bootBefore == bootAfter) {
      continue;
    }
    bool matches(Map frame) =>
        frame['state'] == 'ready' &&
        frame['device_id'] == device.id &&
        frame['serial'] == device.serial &&
        frame['article_id'] == article.articleId &&
        frame['article_revision_id'] == article.id &&
        frame['hardware'] == device.hardwareUid &&
        frame['role'] == article.role;
    if (!matches(before) || !matches(after)) continue;
    final bytes = <int>[];
    for (var i = 0; i < key.length; i += 2) {
      bytes.add(int.parse(key.substring(i, i + 2), radix: 16));
    }
    if (sha256.convert(bytes).toString() != report['public_key_sha256']) {
      continue;
    }
    candidates.add(key);
  }
  if (candidates.length != 1) {
    throw const FormatException(
      'Verified provisioning key evidence is missing or ambiguous',
    );
  }
  return candidates.single;
}
