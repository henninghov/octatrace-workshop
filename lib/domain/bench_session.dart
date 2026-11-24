import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'bench_definition.dart';
import 'bench_sync.dart';
import 'factory_enrollment.dart';
import 'provisioning.dart';
import 'registry.dart';
import 'ports.dart';

String benchHash(String text) => sha256.convert(utf8.encode(text)).toString();

abstract interface class BenchStore {
  Future<void> saveBench(Json report);
  Future<Json> reopenBench(String account, String id);
  Future<List<Json>> benchHistory(String account);
  Future<({String path, String digest, int bytes})> exportBench(
    Json report,
    String folder,
  );
}

typedef IdentityReader = Future<Json> Function(
  String account,
  ProvisionedIdentityRead selection, {
  void Function(Json diagnostic)? onDiagnostic,
});
typedef InspectionReader = Future<Json> Function(
  String account,
  ProvisionedIdentityRead selection,
  String publicKey, {
  void Function(Json diagnostic)? onDiagnostic,
});

typedef DeliveryReader = Future<Json> Function(
  String account,
  ProvisionedIdentityRead selection,
  String publicKey,
  PublicFactoryCredential credential, {
  void Function(Json diagnostic)? onDiagnostic,
});

typedef InstallationReader = Future<Json> Function(
  String account,
  ProvisionedIdentityRead selection,
  String publicKey,
  PublicFactoryCredential credential,
  String attemptId,
  int fault,
  Future<Json> Function(Json review) confirm, {
  void Function(Json diagnostic)? onDiagnostic,
});

typedef PreparationReader = Future<Json> Function(
  String account,
  ProvisionedIdentityRead selection,
  String publicKey,
  String attemptId,
  Future<Json> Function(Json review) confirm, {
  void Function(Json diagnostic)? onDiagnostic,
});

/// A session belongs to exactly one signed-in operator. Only this instance can
/// advance its active attempt. Historical attempts are opened for review/export.
final class BenchSession {
  BenchSession(
    this.account,
    BenchDefinition definition,
    this.store,
    this.discover,
    this.cancelRunner,
    this.readIdentity,
    this.buildFingerprint,
    this.newId,
    this.now, {
    this.sync,
    this.inspectionDefinition,
    this.readInspection,
    this.readinessDefinition,
    this.readReadiness,
    this.lookupPublicKey,
    this.deliveryDefinition,
    this.readDelivery,
    this.lookupCredential,
    this.installationDefinition,
    this.intentStopDefinition,
    this.readInstallation,
    this.preparationDefinition,
    this.readPreparation,
  }) : definition = definition,
       identityDefinition = definition;
  final String account;
  BenchDefinition definition;
  final BenchDefinition identityDefinition;
  final BenchDefinition? inspectionDefinition;
  final InspectionReader? readInspection;
  final BenchDefinition? readinessDefinition;
  final InspectionReader? readReadiness;
  final Future<String> Function(DeviceRecord, ArticleRevision)? lookupPublicKey;
  final BenchDefinition? deliveryDefinition;
  final DeliveryReader? readDelivery;
  final BenchDefinition? installationDefinition, intentStopDefinition;
  final InstallationReader? readInstallation;
  final BenchDefinition? preparationDefinition;
  final PreparationReader? readPreparation;
  void Function()? onChanged;
  Json? installationReview;
  bool confirmationSaving = false;
  Completer<bool>? _confirmation;
  ProvisionedIdentityRead? _installationRead;
  String? _installationKey;
  PublicFactoryCredential? _installationCredential;
  final Future<PublicFactoryCredential> Function(
    DeviceRecord,
    ArticleRevision,
    String,
  )?
  lookupCredential;
  bool get isInspection =>
      definition.guide['key'] == 'c82-credential-inspection-device';

  bool get isReadiness =>
      definition.guide['key'] == 'c82-credential-startup-device';
  bool get isDelivery =>
      definition.guide['key'] == 'c822-credential-delivery-device';
  bool get isInstallation =>
      definition.guide['key'] == 'c823-credential-installation-device' ||
      isIntentStop;
  bool get isIntentStop =>
      definition.guide['key'] == 'c823-credential-intent-stop-device';
  bool get isPreparation =>
      definition.guide['key'] == 'c823-credential-preparation-device';
  bool get isWrite => isInstallation || isPreparation;
  bool get isCredentialTest =>
      isInspection || isReadiness || isDelivery || isWrite;

  void selectDefinition(BenchDefinition value) {
    if (active || pending != null) {
      throw StateError('Finish the current attempt first');
    }
    if (value != identityDefinition &&
        value != inspectionDefinition &&
        value != readinessDefinition &&
        value != deliveryDefinition &&
        value != installationDefinition &&
        value != intentStopDefinition &&
        value != preparationDefinition) {
      throw StateError('Unknown test definition');
    }
    definition = value;
    report = null;
  }

  Future<Json> _reviewInstallation(Json review) async {
    if (_stopReason != null) throw BenchCancelled();
    final updated = jsonDecode(jsonEncode(report)) as Json;
    updated['generation']++;
    updated['installation_review'] = review;
    updated['installation_consent'] = {
      'status': 'Awaiting confirmation',
      'operator': account,
      'at': _time,
    };
    await _save(updated);
    if (_stopReason != null) throw BenchCancelled();
    _confirmation = Completer<bool>();
    installationReview = review;
    onChanged?.call();
    final accepted = await _confirmation!.future;
    return {'confirm': accepted, 'review_token': review['review_token']};
  }

  Future<void> respondInstallation(bool accepted) async {
    final reply = _confirmation;
    final review = installationReview;
    if (reply == null ||
        reply.isCompleted ||
        review == null ||
        confirmationSaving) {
      throw StateError('No current installation confirmation');
    }
    confirmationSaving = true;
    onChanged?.call();
    var authorized = false;
    try {
      if (accepted) {
        final selected = _installationRead!;
        if (isPreparation) {
          if (await lookupPublicKey!(selected.device, selected.article) !=
              _installationKey) {
            throw const ProvisioningFailure(
              'Registry identity changed; inspect again.',
            );
          }
        } else {
          final fresh = await lookupCredential!(
            selected.device,
            selected.article,
            _installationKey!,
          );
          if (fresh.digest != _installationCredential!.digest) {
            throw const ProvisioningFailure(
              'Credential changed; verify again before confirming.',
            );
          }
        }
      }
      if (_stopReason != null || reply.isCompleted) return;
      final updated = jsonDecode(jsonEncode(report)) as Json;
      updated['generation']++;
      updated['installation_consent'] = {
        'status': accepted ? 'Approved' : 'Cancelled',
        'operator': account,
        'at': _time,
        'review_token': review['review_token'],
      };
      await _save(updated);
      authorized = accepted;
    } finally {
      if (!reply.isCompleted) reply.complete(authorized);
      installationReview = null;
      confirmationSaving = false;
      onChanged?.call();
    }
  }

  final BenchStore store;
  final Future<Json> Function(String, BenchDefinition) discover;
  final Future<void> Function() cancelRunner;
  final IdentityReader readIdentity;
  final Future<String> Function() buildFingerprint;
  final String Function() newId;
  final DateTime Function() now;

  final BenchSync? sync;
  final verifiedGenerations = <String, int>{};
  List<Json> sharedHistory = [];
  bool get _current => _stopReason == null;

  Future<void> syncSelected() async {
    final id = report!['id'] as String;
    await sync!.upload(account, id, store, () => _current);
    await refresh();
  }

  Future<void> loadSharedHistory() async {
    sharedHistory = await sync!.history(account, () => _current);
  }

  final sharedArtifacts = <(String, int, String), String>{};
  (String, int, String) attachmentKey(Json row, Json artifact) =>
      (row['header']['id'], row['result']['generation'], artifact['sha256']);
  Future<void> readSharedArtifact(Json row, Json artifact) async {
    final bytes = await sync!.readArtifact(
      account,
      row,
      artifact,
      () => _current,
    );
    sharedArtifacts[attachmentKey(row, artifact)] = bytes;
  }

  Json? report, pending;
  List<Json> history = [];
  bool active = false;
  String? _stopReason;
  Future<void>? _operation, _stopping;
  bool _reading = false;
  String get _time => now().toUtc().toIso8601String();
  int get next =>
      (report!['steps'] as List).indexWhere((s) => s['status'] == 'Not run') +
      1;

  Future<void> perform(Future<void> Function() work) {
    if (_operation != null || _stopping != null) {
      throw StateError('Bench action already running');
    }
    return _operation = Future.sync(work).whenComplete(() => _operation = null);
  }

  Future<void> refresh() async {
    history = await store.benchHistory(account);
    verifiedGenerations.clear();
    for (final r in history) {
      if (await sync?.hasReceipt(r) == true) {
        verifiedGenerations[r['id']] = r['generation'];
      }
    }
  }

  Future<void> open(String id) async {
    if (active) throw StateError('Finish the current attempt first');
    report = await store.reopenBench(account, id);
  }

  Future<void> start(DeviceRecord device, ArticleRevision article) async {
    if (active ||
        pending != null ||
        device.state != 'provisioned' ||
        device.revisionId != article.id) {
      throw StateError(
        'Select a provisioned device with its exact article revision',
      );
    }
    final build = definition.builds.singleWhere((b) => b.role == article.role);
    final fingerprint = await buildFingerprint();
    if (!hexId(fingerprint, 64)) {
      throw const FormatException('Workshop build fingerprint unavailable');
    }
    await refresh();
    final previous = history
        .where(
          (r) =>
              r['device']['id'] == device.id &&
              r['definition_key'] == definition.guide['key'],
        )
        .firstOrNull;
    final selected = report;
    final prior =
        selected?['device']['id'] == device.id &&
            selected?['definition_key'] == definition.guide['key']
        ? selected
        : previous;
    final timestamp = _time;
    final initial = <String, dynamic>{
      'format': 1,
      'id': newId(),
      'operator': account,
      'generation': 1,
      'prior_attempt': prior?['id'],
      if (isInstallation && !isIntentStop)
        'recovery_of': history
            .where(
              (r) =>
                  r['device']['id'] == device.id &&
                  r['definition_key'] == 'c823-credential-intent-stop-device' &&
                  r['steps'][3]['status'] == 'Passed',
            )
            .firstOrNull?['id'],
      'started_at': timestamp,
      'ended_at': null,
      'outcome': 'Incomplete',
      'sync': 'Local only',
      'definition_key': definition.guide['key'],
      'definition_revision': definition.guide['revision'],
      'definition_snapshot': definition.snapshot,
      'definition_sha256': definition.snapshotDigest,
      'workshop_sha256': fingerprint,
      'device': {
        'id': device.id,
        'serial': device.serial,
        'role': article.role,
        'article_id': article.articleId,
        'revision': article.id,
        'hardware': device.hardwareUid,
        'claimed': device.ownerId != null,
      },
      'firmware': {
        'role': build.role,
        'version': build.version,
        'source': build.source,
        'artifact': build.artifact,
      },
      'steps': [
        for (final s in definition.guide['steps'])
          {
            'number': s['number'],
            'actor': s['actor'],
            'evaluation': s['evaluation'],
            'status': s['number'] <= 2 ? 'Passed' : 'Not run',
            if (s['number'] <= 2) 'at': timestamp,
            if (s['number'] == 1)
              'evidence': 'Operator selected this device and build.',
            if (s['number'] == 2)
              'evidence': 'Started attempt persisted locally.',
          },
      ],
      'artifacts': <Json>[],
      'exports': <Json>[],
    };
    active = true;
    report = null;
    await _save(initial);
  }

  Future<void> _save(Json value) async {
    pending = value;
    await store.saveBench(value);
    pending = null;
    report = value;
    history = [value, ...history.where((r) => r['id'] != value['id'])];
    if (value['ended_at'] != null) active = false;
  }

  Future<void> retrySave() => _save(pending!);

  Json _change(int step, String status, Object evidence, {String? outcome}) {
    final updated = jsonDecode(jsonEncode(report)) as Json;
    updated['generation']++;
    updated['steps'][step - 1].addAll({
      'status': status,
      'at': _time,
      'evidence': evidence,
    });
    if (outcome != null) {
      updated['outcome'] = outcome;
      updated['ended_at'] = _time;
    }
    return updated;
  }

  void _require(int step) {
    if (!active || pending != null || next != step) {
      throw StateError('This step is unavailable');
    }
  }

  Future<void> connected(DeviceRecord device, ArticleRevision article) async {
    _require(3);
    await _save(
      _change(3, 'Passed', 'Operator acknowledged the USB cable connection.'),
    );
    if (_stopReason == null) await readDevice(device, article);
  }

  Future<void> readDevice(DeviceRecord device, ArticleRevision article) async {
    _require(4);
    Json? diagnostic;
    Json result;
    String status;
    try {
      _reading = true;
      final response = await discover(account, definition);
      if (_stopReason != null) return;
      final targets = UsbInventory.fromJson(response).targets.where(
        (t) => t.hardware == report!['device']['hardware'] && t.mode == 'app',
      );
      final target = targets.singleOrNull;
      if (target == null ||
          device.id != report!['device']['id'] ||
          device.hardwareUid != report!['device']['hardware'] ||
          device.revisionId != report!['device']['revision'] ||
          article.role != report!['device']['role'] ||
          article.articleId != report!['device']['article_id'] ||
          device.serial != report!['device']['serial']) {
        throw const BenchBlocked(
          'Selected application-mode USB target or registry binding is unavailable.',
        );
      }
      final build = definition.builds.singleWhere(
        (b) => b.role == report!['firmware']['role'],
      );
      final read = definition.admit(
        device: device,
        article: article,
        target: target,
        build: build,
      );
      late final Json frame;
      if (isPreparation) {
        if (readPreparation == null ||
            readInspection == null ||
            lookupPublicKey == null) {
          throw const BenchBlocked(
            'Preparation runner or verified identity key unavailable',
          );
        }
        final key = await lookupPublicKey!(device, article);
        if (_stopReason != null) return;
        _installationRead = read;
        _installationKey = key;
        final prepared = await readPreparation!(
          account,
          read,
          key,
          report!['id'] as String,
          _reviewInstallation,
          onDiagnostic: (data) => diagnostic = data,
        );
        frame = {'state': prepared['preparation_result']['state'], ...prepared};
      } else if (isCredentialTest) {
        final reader = isReadiness ? readReadiness : readInspection;
        if (lookupPublicKey == null ||
            (isDelivery || isInstallation
                ? (isInstallation
                          ? readInstallation == null || readReadiness == null
                          : readDelivery == null) ||
                      lookupCredential == null
                : reader == null)) {
          throw const BenchBlocked(
            'Verified identity key or inspection runner unavailable',
          );
        }
        late final String publicKey;
        try {
          publicKey = await lookupPublicKey!(device, article);
        } on FormatException {
          throw const BenchBlocked(
            'Verified provisioning key evidence is missing or ambiguous.',
          );
        }
        if (_stopReason != null) return;
        if (isReadiness) {
          _installationRead = read;
          _installationKey = publicKey;
        }
        if (isDelivery || isInstallation) {
          final credential = await lookupCredential!(
            device,
            article,
            publicKey,
          );
          if (_stopReason != null) return;
          if (isInstallation) {
            _installationRead = read;
            _installationKey = publicKey;
            _installationCredential = credential;
            final installed = await readInstallation!(
              account,
              read,
              publicKey,
              credential,
              report!['id'] as String,
              isIntentStop ? 1 : 0,
              _reviewInstallation,
              onDiagnostic: (data) => diagnostic = data,
            );
            frame = {
              'state': installed['installation_proof']['journal_state'],
              ...installed,
            };
          } else {
            final result = await readDelivery!(
              account,
              read,
              publicKey,
              credential,
              onDiagnostic: (data) => diagnostic = data,
            );
            frame = {'state': 'verified', ...result};
          }
        } else {
          frame = await reader!(
            account,
            read,
            publicKey,
            onDiagnostic: (data) => diagnostic = data,
          );
        }
      } else {
        frame = await readIdentity(
          account,
          read,
          onDiagnostic: (data) => diagnostic = data,
        );
      }
      result = {'frame': frame};
      status = 'Passed';
    } catch (error) {
      status = error is BenchCancelled
          ? 'Incomplete'
          : error is BenchBlocked ||
                (error is FormatException &&
                    error.message == 'Ambiguous USB inventory')
          ? 'Blocked'
          : 'Failed';
      result = {
        'error': error is ProvisioningFailure
            ? error.message
            : error.toString(),
      };
    } finally {
      _reading = false;
      final reply = _confirmation;
      if (reply != null && !reply.isCompleted) reply.complete(false);
      _confirmation = null;
      installationReview = null;
      confirmationSaving = false;
      onChanged?.call();
    }
    if (pending != null && isWrite) {
      // Preserve the unsaved review/consent. No authorization was sent after a
      // failed save; retrying persistence must not restart the USB operation.
      final unsaved = jsonDecode(jsonEncode(pending)) as Json;
      unsaved['steps'][3].addAll({
        'status': 'Incomplete',
        'at': _time,
        'evidence': {'local_save_failed': true, 'result': result},
      });
      unsaved['outcome'] = 'Incomplete';
      unsaved['ended_at'] = _time;
      if (unsaved['installation_consent'] is Json) {
        unsaved['installation_consent']['status'] =
            'Not sent; local save failed';
      }
      pending = unsaved;
      return;
    }
    final interruption = _stopReason;
    if (interruption != null) {
      // Retain the owner's bounded diagnostic on this attempt. A late frame
      // cannot become a passed step after cancellation or logout.
      status = 'Incomplete';
      result = {
        'interruption': interruption,
        if (isWrite) 'late_result': result,
      };
    }
    final updated = _change(
      4,
      status,
      result,
      outcome: interruption != null
          ? _interruptedOutcome(interruption)
          : status == 'Passed'
          ? null
          : status,
    );
    final raw = jsonEncode(diagnostic ?? result);
    updated['artifacts'].add({
      'run_id': report!['id'],
      'step': 4,
      'type': 'application/json',
      'bytes': utf8.encode(raw).length,
      'sha256': benchHash(raw),
      'content': raw,
    });
    await _save(updated);
  }

  Future<void> observe(String value, {bool unavailable = false}) async {
    _require(5);
    if (isWrite || isReadiness) {
      throw StateError('Confirm the restart and use the automatic check');
    }
    final text = value.trim();
    if (text.isEmpty || text.length > 256) {
      throw const FormatException(
        'Enter the label or a reason (1–256 characters).',
      );
    }
    final expected = isCredentialTest
        ? report!['steps'][3]['evidence']['frame']['state']
        : report!['device']['serial'];
    final status = unavailable
        ? 'Incomplete'
        : text == expected
        ? 'Passed'
        : 'Failed';
    final updated = _change(5, status, {
      'operator': account,
      'observation': text,
      'unavailable': unavailable,
    }, outcome: status == 'Passed' ? null : status);
    await _save(updated);
    if (status == 'Passed' && _stopReason == null) await verifyReopen();
  }

  /// Save the operator's confirmation before refreshing registry or reading USB.
  Future<void> checkAfterRestart({required bool confirmed}) async {
    _require(5);
    if (!confirmed ||
        !(isWrite || isReadiness) ||
        definition.guide['revision'] != 2) {
      throw StateError('Confirm that the selected device was restarted');
    }
    final selected = _installationRead;
    final key = _installationKey;
    if (selected == null || key == null || lookupPublicKey == null) {
      throw StateError('The baseline identity is unavailable');
    }
    final initial = report!['steps'][3]['evidence']['frame'] as Json;
    final proof = isReadiness
        ? initial
        : isPreparation
        ? initial['preparation_result'] as Json
        : initial['installation_proof'] as Json;
    final expected = <String, dynamic>{
      'state': initial['state'],
      'boot': proof['boot'],
      if (initial['state'] == 'ready') ...{
        'revision': isReadiness
            ? proof['revision']
            : proof['credential_revision'],
        'content_id': proof['content_id'],
      },
    };
    final confirmation = {'operator': account, 'at': _time, 'confirmed': true};
    final saved = jsonDecode(jsonEncode(report)) as Json;
    saved['generation']++;
    saved['steps'][4]['evidence'] = {
      'restart_confirmation': confirmation,
      'expected_restart': expected,
    };
    await _save(saved);
    Json? restart, diagnostic, registryCheck;
    String? error;
    Object? accessError;
    var status = 'Passed';
    _reading = true;
    try {
      if (_stopReason != null) throw BenchCancelled();
      if (await lookupPublicKey!(selected.device, selected.article) != key) {
        throw const ProvisioningFailure(
          'Registry identity or ownership changed.',
        );
      }
      registryCheck = {
        'matched': true,
        'claimed': selected.device.ownerId != null,
        if (selected.device.ownerId != null)
          'owner_sha256': benchHash(selected.device.ownerId!),
        'checked_at': _time,
      };
      if (_stopReason != null) throw BenchCancelled();
      restart = await (isPreparation ? readInspection! : readReadiness!)(
        account,
        selected,
        key,
        onDiagnostic: (value) => diagnostic = value,
      );
      if (_stopReason != null) throw BenchCancelled();
      if (restart['boot'] == expected['boot']) {
        throw const ProvisioningFailure(
          'The device is still on the baseline boot.',
        );
      }
      if (restart['state'] != expected['state']) {
        throw const ProvisioningFailure(
          'The measured state differs from the expected state.',
        );
      }
      if (expected['state'] == 'ready' &&
          (restart['revision'] != expected['revision'] ||
              restart['content_id'] != expected['content_id'])) {
        throw const ProvisioningFailure(
          'The credential revision or content differs.',
        );
      }
    } catch (failure) {
      if (failure is SessionExpired || failure is OperatorDenied) {
        accessError = failure;
      }
      status = _stopReason == null && accessError == null
          ? 'Failed'
          : 'Incomplete';
      error = failure is ProvisioningFailure
          ? failure.message
          : failure is SessionExpired || failure is OperatorDenied
          ? 'Operator access is no longer available.'
          : failure.toString();
    } finally {
      _reading = false;
    }
    final updated = _change(
      5,
      status,
      {
        'restart_confirmation': confirmation,
        'expected_restart': expected,
        'registry_check': ?registryCheck,
        'automatic_restart_check': ?restart,
        'automatic_error': ?error,
      },
      outcome: status == 'Passed'
          ? null
          : _stopReason != null
          ? _interruptedOutcome(_stopReason!)
          : accessError != null
          ? 'Interrupted'
          : status,
    );
    if (diagnostic != null) {
      final raw = jsonEncode(diagnostic);
      updated['artifacts'].add({
        'run_id': report!['id'],
        'step': 5,
        'type': 'application/json',
        'bytes': utf8.encode(raw).length,
        'sha256': benchHash(raw),
        'content': raw,
      });
    }
    await _save(updated);
    if (accessError != null) throw accessError;
    if (status == 'Passed' && _stopReason == null) await verifyReopen();
  }

  Future<void> verifyReopen() async {
    _require(6);
    final reopened = await store.reopenBench(account, report!['id']);
    if (jsonEncode(reopened) != jsonEncode(report)) {
      throw const FormatException('Reopened report differs');
    }
    if (_stopReason == null) {
      final review = _change(6, 'Passed', {
        'report': report!['id'],
        'snapshot_sha256': benchHash(jsonEncode(reopened)),
      });
      review['outcome'] = 'Awaiting export';
      await _save(review);
    }
  }

  Future<String> export(String folder) async {
    final current = await store.reopenBench(account, report!['id']);
    if (pending != null || jsonEncode(current) != jsonEncode(report)) {
      throw StateError('Reopen the saved attempt before export');
    }
    if (_stopReason != null) {
      throw StateError('Export interrupted before publication');
    }
    final finishing = next == 7 && current['outcome'] == 'Awaiting export';
    if (active && !finishing) {
      throw StateError('Finish the guide before export');
    }
    final exported = finishing
        ? _change(7, 'Passed', {
            'operator': account,
            'action': 'Export report',
          }, outcome: 'Passed')
        : current;
    late final ({String path, String digest, int bytes}) receipt;
    try {
      receipt = await store.exportBench(exported, folder);
    } catch (error) {
      if (finishing && _stopReason == null) {
        await _save(
          _change(7, 'Incomplete', {
            'export_error': error.toString(),
          }, outcome: 'Incomplete'),
        );
      }
      rethrow;
    }
    if (finishing) {
      exported['exports'].add({
        'path': receipt.path,
        'sha256': receipt.digest,
        'bytes': receipt.bytes,
      });
      await _save(exported);
    }
    return receipt.path;
  }

  String _interruptedOutcome(String reason) =>
      reason == 'Operator cancelled' ? 'Cancelled' : 'Interrupted';

  Future<void> stop(String reason) =>
      _stopping ??= _stop(reason).whenComplete(() {
        _stopping = null;
        _stopReason = null;
      });

  Future<void> _stop(String reason) async {
    _stopReason = reason;
    final confirmation = _confirmation;
    if (confirmation != null && !confirmation.isCompleted) {
      confirmation.complete(false);
    }
    installationReview = null;
    onChanged?.call();
    try {
      if (_reading) await cancelRunner();
    } finally {
      try {
        await _operation;
      } catch (_) {
        /* Keep the last durable step. */
      }
      if (active) {
        if (pending != null) await retrySave();
        if (report?['outcome'] == 'Awaiting export' &&
            reason != 'Operator cancelled') {
          active = false;
        } else if (active) {
          await _save(
            _change(
              next,
              'Incomplete',
              reason,
              outcome: _interruptedOutcome(reason),
            ),
          );
        }
      }
    }
  }
}

final class BenchBlocked extends FormatException {
  const BenchBlocked(super.message);
}
