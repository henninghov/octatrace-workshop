import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'bench_definition.dart';
import 'bench_identity_key.dart';
import 'provisioning.dart';
import 'registry.dart';

/// Durable update attempts are private and never silently cleared after a write.
abstract interface class ClaimedUpdateStore {
  Future<Json?> pendingUpdate(String account, String hardware);
  Future<void> beginUpdate(Json record);
  Future<void> saveUpdate(Json record);
  Future<void> releaseUpdate(Json record);
  Future<String> exportUpdate(Json record, String folder);
}

typedef UpdateProof = Future<Json> Function(
  String account,
  Json selection,
  BenchDefinition definition,
);

/// One supervised test-image update. Ownership is checked, never modified.
final class ClaimedUpdateSession {
  ClaimedUpdateSession({
    required this.account,
    required this.device,
    required this.article,
    required this.gateway,
    required this.runner,
    required this.prove,
    required this.store,
    required this.definition,
    required this.guideSnapshot,
    required this.newId,
    required this.now,
    required this.workshopFingerprint,
    required this.current,
  }) {
    final guideHash = sha256.convert(utf8.encode(guideSnapshot)).toString();
    if (!{
      '758fe6368bc74200fe48c8e09786cf72496be413863544807af7da2cd2c43db5',
      'b432bea67e1ef4a8ce05f89375cea8155f5ac83967f7b949a24c87b89031a359',
      '494bc4f720624d762e140fed819ac1e6dc64ccb2edfd7a925e1d4d6a74bcdc60',
      'fdb74171e6d516cc441403229f496a66e95f4cb463099597515ae2a73f57bf14',
      '322b1a6fc8df3c928c20b024b24458c6490e00c18e7c4cc48bbc53c974e20c28',
      '1850aef011325b62f3e76e96926b8e706e741a90ba78811cdb8a7fc5a0ebfd83',
      '4e0b448ec19240684b43f150831c1f17ab779b00847bdb2afe57f2f921f1552e',
      '6ec1bc2f34feda1af1cd2403fa316aaaf74d0ce370bd3377efc48ec307084a9a',
      'b3b61fe8a2d5f3b4d0db525fd36fc21c4c7486c98f5aa41f0f75e4393e582679',
      'e1a5bf79c6ece16a30b85b7278e69b87cd8c9151dfa7e1f23320ddfcd340983d',
      '1b0f31d41d881d832d4319f8c91208860b13505b81494d430a8b584b46ba0ba0',
      'a5617e7cccb7df215693b281c089ab8c52ba0809a9c7185f109d586ea65cef71',
    }.contains(guideHash)) {
      throw const FormatException('Unknown firmware update guide');
    }
    guide = jsonDecode(guideSnapshot) as Json;
    if (definition.snapshotDigest != guide['owner_dependency_guide_sha256']) {
      throw const FormatException('Update owner dependencies differ');
    }
  }

  final String account;
  final DeviceRecord device;
  final ArticleRevision article;
  final WorkshopGateway gateway;
  final ProvisioningRunner runner;
  final UpdateProof prove;
  final ClaimedUpdateStore store;
  final BenchDefinition definition;
  final String guideSnapshot;
  final String Function() newId;
  final DateTime Function() now;
  final Future<String> Function() workshopFingerprint;
  final bool Function() current;
  late final Json guide;
  Json? report;
  Json? priorPending;
  bool busy = false;
  String get phase => priorPending != null
      ? 'review_required'
      : (report?['phase'] as String? ?? 'new');

  Future<bool> checkPending() async {
    _checkSession();
    priorPending = await store.pendingUpdate(account, device.hardwareUid!);
    _checkSession();
    return priorPending != null;
  }

  void _checkSession() {
    if (!current() || gateway.accountId != account) throw SessionExpired();
  }

  Future<String> _currentKey() async {
    _checkSession();
    await gateway.authorizeOperator();
    _checkSession();
    final registry = await gateway.load();
    _checkSession();
    final matches = registry.devices.where((d) => d.id == device.id).toList();
    final revisions = registry.articles
        .where((a) => a.id == article.id)
        .toList();
    if (device.ownerId == null ||
        !device.serial.startsWith('D') ||
        device.state != 'provisioned' ||
        article.role != 'Core' ||
        device.revisionId != article.id ||
        device.hardwareUid == null ||
        matches.length != 1 ||
        revisions.length != 1 ||
        revisions.single.articleId != article.articleId ||
        revisions.single.role != article.role ||
        revisions.single.revision != article.revision ||
        matches.single.ownerId != device.ownerId ||
        matches.single.state != device.state ||
        matches.single.hardwareUid != device.hardwareUid ||
        matches.single.revisionId != device.revisionId ||
        matches.single.serial != device.serial) {
      throw const FormatException(
        'Claimed CORE binding changed or is unavailable',
      );
    }
    return provisionedKey(registry, device, article);
  }

  Json _selection(String source, String publicKey) => {
    'role': article.role,
    'device_id': device.id,
    'serial': device.serial,
    'article_id': article.articleId,
    'article_revision_id': article.id,
    'hardware': device.hardwareUid,
    'public_key': publicKey,
    'source': source,
  };

  void _checkProof(Json proof, String source, String publicKey) {
    if (proof['state'] != 'ready' ||
        proof['busy'] != false ||
        proof['failed'] != false ||
        proof['role'] != article.role ||
        proof['device_id'] != device.id ||
        proof['serial'] != device.serial ||
        proof['article_id'] != article.articleId ||
        proof['article_revision_id'] != article.id ||
        proof['hardware'] != device.hardwareUid ||
        proof['build'] != source ||
        proof['public_key'] != publicKey ||
        !hexId(proof['boot'] as String? ?? '', 32) ||
        !hexId(proof['challenge'] as String? ?? '', 64) ||
        !hexId(proof['signature'] as String? ?? '', 128)) {
      throw const FormatException('Update identity proof binding changed');
    }
  }

  Future<UsbInventory> _inventory() async {
    _checkSession();
    final result = await runner.execute(account: account, command: 'inventory');
    _checkSession();
    return UsbInventory.fromJson(result);
  }

  Future<void> preflight({required bool operatorReady}) async {
    if (!operatorReady) {
      throw StateError('Confirm CORE is stopped, saved and safely powered');
    }
    if (busy || phase != 'new') {
      throw StateError('Update attempt already started');
    }
    busy = true;
    try {
      final key = await _currentKey();
      final inventory = await _inventory();
      final targets = inventory.targets.where(
        (t) => t.hardware == device.hardwareUid && t.mode == 'app',
      );
      if (inventory.targets.length != 1 || targets.length != 1) {
        throw const FormatException(
          'Connect the selected CORE in application mode',
        );
      }
      final builds = inventory.builds.where(
        (b) =>
            b.role == 'Core' &&
            b.source == guide['after_source'] &&
            b.artifact == guide['after_artifact'],
      );
      if (builds.length != 1) {
        throw const FormatException('The qualified CORE image is unavailable');
      }
      final bundle = await workshopFingerprint();
      _checkSession();
      if (!hexId(bundle, 64)) {
        throw const FormatException('Workshop build fingerprint unavailable');
      }
      final r = <String, dynamic>{
        'format': 1,
        'id': newId(),
        'account': account,
        'device_id': device.id,
        'hardware': device.hardwareUid,
        'owner_id': device.ownerId,
        'serial': device.serial,
        'role': article.role,
        'operator_ready_confirmation': true,
        'before_source': guide['before_source'],
        'after_source': guide['after_source'],
        'after_artifact': guide['after_artifact'],
        'guide_snapshot': guideSnapshot,
        'guide_sha256': sha256.convert(utf8.encode(guideSnapshot)).toString(),
        'proof_runner_sha256': guide['proof_runner_sha256'],
        'owner_dependency_guide_sha256': definition.snapshotDigest,
        'workshop_sha256': bundle,
        'started_at': now().toUtc().toIso8601String(),
        'phase': 'preflight',
        'generation': 1,
      };
      await store.beginUpdate(r);
      report = r;
      try {
        _checkSession();
        final before = await prove(
          account,
          _selection(guide['before_source'] as String, key),
          definition,
        );
        _checkSession();
        _checkProof(before, guide['before_source'] as String, key);
        r['before_proof'] = before;
        r['before_verified_at'] = now().toUtc().toIso8601String();
        r['phase'] = 'awaiting_bootloader';
        r['generation']++;
        await store.saveUpdate(r);
      } catch (_) {
        r['phase'] = 'preflight_failed';
        r['generation']++;
        await store.saveUpdate(r);
        await store.releaseUpdate(r);
        rethrow;
      }
    } finally {
      busy = false;
    }
  }

  Future<String> export(String folder) async {
    _checkSession();
    final saved = report ?? priorPending;
    if (busy || saved == null) throw StateError('No saved update report');
    return store.exportUpdate(saved, folder);
  }

  Future<void> cancelBeforeWrite() async {
    if (busy || phase != 'awaiting_bootloader') {
      throw StateError('Cannot cancel this update without review');
    }
    final r = report!;
    r['phase'] = 'cancelled_before_write';
    r['generation']++;
    await store.saveUpdate(r);
    await store.releaseUpdate(r);
  }

  Future<void> install({required bool confirmed}) async {
    if (busy || phase != 'awaiting_bootloader' || !confirmed) {
      throw StateError('Review the selected update before installation');
    }
    busy = true;
    try {
      final r = report!;
      final key = await _currentKey();
      final before = r['before_proof'] as Json;
      if (before['public_key'] != key) {
        throw const FormatException('Verified device key changed');
      }
      final inventory = await _inventory();
      final targets = inventory.targets.where(
        (t) => t.hardware == device.hardwareUid && t.mode == 'bootloader',
      );
      final builds = inventory.builds.where(
        (b) =>
            b.role == 'Core' &&
            b.source == guide['after_source'] &&
            b.artifact == guide['after_artifact'],
      );
      if (inventory.targets.length != 1 ||
          targets.length != 1 ||
          builds.length != 1) {
        throw const FormatException(
          'Matching CORE bootloader or qualified image is unavailable',
        );
      }
      final target = targets.single, build = builds.single;
      r['write_started_at'] = now().toUtc().toIso8601String();
      r['phase'] = 'write_started';
      r['generation']++;
      await store.saveUpdate(
        r,
      ); // durable intent precedes the first application write
      _checkSession();
      try {
        final installed = await runner.execute(
          account: account,
          command: 'install',
          parameters: {
            'hardware': target.hardware,
            'manifest': build.manifest,
            'volume': target.volume,
          },
        );
        _checkSession();
        if (installed['installed'] != true ||
            installed['hardware'] != device.hardwareUid ||
            installed['source'] != build.source ||
            installed['artifact'] != build.artifact) {
          throw const FormatException(
            'Installed image evidence does not match',
          );
        }
        r['installation'] = installed;
        r['phase'] = 'awaiting_postflight';
        r['generation']++;
        await store.saveUpdate(r);
        final currentKey = await _currentKey();
        if (currentKey != key) {
          throw const FormatException('Device key changed');
        }
        final after = await prove(
          account,
          _selection(build.source, key),
          definition,
        );
        _checkSession();
        _checkProof(after, build.source, key);
        if (after['boot'] == before['boot']) {
          throw const FormatException('A new boot was not confirmed');
        }
        r['after_proof'] = after;
        r['verified_at'] = now().toUtc().toIso8601String();
        r['phase'] = 'verified';
        r['generation']++;
        await store.saveUpdate(r);
        await store.releaseUpdate(r);
      } catch (_) {
        // Never retry a possibly started write. Keep the durable active lock.
        r['phase'] = 'interrupted_after_write';
        r['generation']++;
        await store.saveUpdate(r);
        rethrow;
      }
    } finally {
      busy = false;
    }
  }
}
