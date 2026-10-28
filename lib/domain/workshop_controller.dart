import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';

import 'ports.dart';
import 'provisioning.dart';
import 'registry.dart';

enum Access { signedOut, sendingLink, awaitingLink, signingIn, denied, ready }

String newRequestId() {
  final random = Random.secure();
  final bytes = List<int>.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  final s = bytes.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
  return '${s.substring(0, 8)}-${s.substring(8, 12)}-${s.substring(12, 16)}-${s.substring(16, 20)}-${s.substring(20)}';
}

final class WorkshopController extends ChangeNotifier {
  WorkshopController(
    this.gateway,
    this.runner,
    this.journal, {
    this.provisioner,
    String Function()? idFactory,
    DateTime Function()? now,
  }) : _idFactory = idFactory ?? newRequestId,
       _now = now ?? DateTime.now;
  final ProvisioningRunner? provisioner;
  final WorkshopGateway gateway;
  final BenchRunner runner;
  final EvidenceStore journal;
  final String Function() _idFactory;
  final DateTime Function() _now;
  Access access = Access.signedOut;
  Registry? registry;
  String? message;
  bool busy = false;
  Json? readback;
  String? readbackDeviceId;
  bool readbackSaved = false;
  int pendingEvidence = 0;
  UsbInventory? usbInventory;
  String? provisioningStage;
  String? provisioningDeviceId;
  ProvisioningOutcome? provisioningOutcome;
  bool _cancelProvisioning = false;
  bool get provisioningAvailable =>
      provisioner != null && gateway is ProvisioningGateway;
  int _epoch = 0;
  bool _disposed = false;
  Completer<void>? _signingIn;
  String? _requestedEmail;
  Uri? _queuedLink;
  Future<void>? _closing;
  Future<void> get closed => _closing ?? Future<void>.value();

  Future<void> _closeResources() async {
    try {
      try {
        await provisioner?.cancel();
      } finally {
        await runner.cancel();
      }
    } finally {
      await gateway.dispose();
    }
  }

  void _changed() {
    if (!_disposed) notifyListeners();
  }

  Future<void> requestLink(String email) async {
    if (busy || access == Access.ready) return;
    final address = email.trim().toLowerCase();
    if (address.length > 254 ||
        !RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$').hasMatch(address)) {
      message = 'Enter your Octatrace account email.';
      _changed();
      return;
    }
    final epoch = ++_epoch;
    final sending = _signingIn = Completer<void>();
    _requestedEmail = null;
    _queuedLink = null;
    registry = null;
    usbInventory = null;
    provisioningStage = null;
    provisioningDeviceId = null;
    provisioningOutcome = null;
    readback = null;
    readbackDeviceId = null;
    readbackSaved = false;
    pendingEvidence = 0;
    access = Access.sendingLink;
    busy = true;
    message = null;
    _changed();
    try {
      await gateway.requestLink(address);
      if (epoch != _epoch) return;
      _requestedEmail = address;
      access = Access.awaitingLink;
      message = 'Check your email. Open the newest sign-in link on this Mac. Keep Workshop open; links expire and work once.';
    } catch (_) {
      if (epoch != _epoch) return;
      access = Access.signedOut;
      message = 'Could not send the sign-in link. Check your email and connection, then try again shortly.';
    } finally {
      sending.complete();
      if (identical(_signingIn, sending)) _signingIn = null;
      if (epoch == _epoch) {
        busy = false;
        _changed();
        final queued = _queuedLink;
        _queuedLink = null;
        if (queued != null && access == Access.awaitingLink) {
          unawaited(acceptLink(queued));
        }
      }
    }
  }

  void linkDeliveryFailed() {
    if (access == Access.ready) return;
    message = 'The sign-in link could not open. Request a new link and keep Workshop open.';
    _changed();
  }

  Future<void> acceptLink(Uri uri) async {
    if (uri.scheme != 'com.octatrace.workshop' ||
        uri.host != 'login-callback' ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        (uri.path.isNotEmpty && uri.path != '/')) {
      return;
    }
    if (access == Access.ready || access == Access.signingIn) return;
    if (access == Access.sendingLink) {
      _queuedLink = uri;
      return;
    }
    final codes = uri.queryParametersAll['code'];
    if (access != Access.awaitingLink ||
        _requestedEmail == null ||
        uri.hasFragment ||
        uri.queryParameters.containsKey('error') ||
        codes?.length != 1 ||
        codes!.single.trim().isEmpty) {
      linkDeliveryFailed();
      return;
    }
    await _completeSignIn(codes.single);
  }

  Future<void> _completeSignIn(String code) async {
    if (busy) return;
    final epoch = ++_epoch;
    final signingIn = _signingIn = Completer<void>();
    busy = true;
    access = Access.signingIn;
    message = null;
    registry = null;
    _changed();
    try {
      await gateway.exchangeLink(code);
      if (gateway.accountEmail?.toLowerCase() != _requestedEmail) {
        throw SessionExpired();
      }
      if (epoch != _epoch) return;
      await gateway.authorizeOperator();
      if (epoch != _epoch) return;
      final data = await gateway.load();
      if (epoch != _epoch) return;
      final pending = await journal.pending(gateway.accountId!);
      if (epoch != _epoch) return;
      registry = data;
      access = Access.ready;
      pendingEvidence = pending.length;
    } catch (error) {
      if (epoch != _epoch) return;
      access = error is OperatorDenied ? Access.denied : Access.signedOut;
      message = error is OperatorDenied
          ? 'This account does not have Workshop operator access.'
          : 'Sign-in failed or this link expired. Request a new link; check your connection and database setup.';
      try {
        await gateway.signOut();
      } catch (_) {
        /* Access is already closed. */
      }
    } finally {
      signingIn.complete();
      if (identical(_signingIn, signingIn)) _signingIn = null;
      if (epoch == _epoch) {
        busy = false;
        _changed();
      }
    }
  }

  Future<void> action(
    Future<void> Function() operation, {
    Future<void> Function()? afterRefresh,
    void Function(Object)? onError,
    bool refreshRegistry = true,
  }) async {
    if (busy || access != Access.ready) return;
    final epoch = _epoch;
    busy = true;
    message = null;
    _changed();
    try {
      await operation();
      if (epoch != _epoch) return;
      final data = refreshRegistry ? await gateway.load() : registry;
      if (epoch == _epoch) {
        registry = data;
        if (afterRefresh != null) await afterRefresh();
      }
    } catch (error) {
      if (epoch != _epoch) return;
      onError?.call(error);
      if (error is OperatorDenied || error is SessionExpired) {
        registry = null;
        readback = null;
        access = Access.denied;
        message = 'Operator access is no longer available. Sign in again.';
      } else if (error is BenchCancelled) {
        message = 'Provisioning stopped. Keep this reservation; committed identity and saved evidence are retained for retry.';
      } else if (error is ProvisioningFailure) {
        message = error.message;
      } else {
        message = 'Operation could not be completed. Your existing records are retained; retry when ready.';
      }
    } finally {
      if (epoch == _epoch) {
        busy = false;
        provisioningStage = null;
        _changed();
      }
    }
  }

  Future<void> refresh() => action(() async {});

  Future<String?> reserve(String revision, String serialClass) async {
    final parameters = '$revision\n$serialClass';
    final epoch = _epoch;
    final account = gateway.accountId;
    if (account == null) return null;
    String? requestId, reservedId;
    await action(
      () async {
        requestId = await journal.reservation(account, parameters, _idFactory);
        if (epoch != _epoch) return;
        reservedId = await gateway.reserve(
          requestId: requestId!,
          revisionId: revision,
          serialClass: serialClass,
        );
      },
      afterRefresh: () =>
          journal.acknowledgeReservation(account, parameters, requestId!),
    );
    return epoch == _epoch && message == null ? reservedId : null;
  }

  Future<void> verify(
    DeviceRecord device,
    ArticleRevision article,
    String port,
    String build, {
    String command = 'identity',
  }) async {
    final epoch = _epoch;
    final account = gateway.accountId;
    if (account == null) return;
    await action(() async {
      readback = null;
      readbackDeviceId = null;
      readbackSaved = false;
      Json result;
      try {
        result = await runner.run(
          port: port,
          role: article.role,
          build: build,
          command: command,
        );
      } catch (error) {
        result = {
          'adapter_outcome': error is BenchCancelled ? 'cancelled' : 'failed',
          'failure_kind': error.runtimeType.toString(),
          'command': command,
          'scope': 'No successful physical result established',
        };
      }
      final id = _idFactory();
      await journal.save(account, {
        'id': id,
        'device_id': device.id,
        'observed_at': _now().toUtc().toIso8601String(),
        'report': result,
      });
      if (epoch != _epoch) return;
      readback = result;
      readbackDeviceId = device.id;
      _changed();
      pendingEvidence = (await journal.pending(account)).length;
      if (epoch != _epoch) return;
      await gateway.recordDiagnostic(
        requestId: id,
        deviceId: device.id,
        report: result,
      );
      await journal.synced(account, id);
      if (epoch == _epoch) {
        readbackSaved = true;
        pendingEvidence = (await journal.pending(account)).length;
        if (result['adapter_outcome'] != null) {
          message =
              'USB action ${result['adapter_outcome']}. Its diagnostic is saved; check the connection and expected build before retrying.';
        }
      }
    });
  }

  Future<void> discoverUsb() => action(() async {
    final epoch = _epoch;
    final inventory = UsbInventory.fromJson(
      await provisioner!.execute(
        account: gateway.accountId!,
        command: 'inventory',
      ),
    );
    if (epoch == _epoch) usbInventory = inventory;
  }, refreshRegistry: false);

  void _provisionCheckpoint(int epoch) {
    if (epoch != _epoch || _cancelProvisioning) throw BenchCancelled();
  }

  void _stage(String value) {
    provisioningStage = value;
    _changed();
  }

  Json _proofReport(Json report) {
    Json frame(String key) {
      final data = report[key] as Json;
      final keys = data.keys.toList()..sort();
      return {for (final name in keys) name: data[name]};
    }

    return {'before': frame('before'), 'after': frame('after')};
  }

  void _confirmed(String deviceId, Json report) {
    final device = registry!.devices.where((d) => d.id == deviceId).firstOrNull;
    if (device == null ||
        device.state != 'provisioned' ||
        device.hardwareUid != (report['after'] as Json)['hardware']) {
      throw const ProvisioningFailure(
        'Registry confirmation is incomplete. Your proof is retained; retry its upload.',
      );
    }
  }

  void _checkProvisioningAttempt(
    Json attempt,
    String requestId,
    DeviceRecord device,
    ArticleRevision article,
    UsbTarget target,
    FirmwareBuild build,
  ) {
    final attemptRole = attempt.containsKey('role') ? attempt['role'] : 'Link';
    if (attemptRole != article.role ||
        attempt['request_id'] != requestId ||
        attempt['device_id'] != device.id ||
        attempt['serial'] != device.serial ||
        attempt['article_id'] != article.articleId ||
        attempt['article_revision_id'] != device.revisionId ||
        attempt['hardware'] != target.hardware ||
        attempt['source'] != build.source ||
        attempt['artifact'] != build.artifact ||
        !{'started', 'completed'}.contains(attempt['state'])) {
      throw const ProvisioningFailure(
        'The server attempt does not match this device/build. Keep the reservation and refresh.',
      );
    }
  }

  Future<void> provision(
    DeviceRecord device,
    ArticleRevision article,
    UsbTarget target,
    FirmwareBuild build, {
    Future<bool> Function(StoragePreparation)? confirmPreparation,
  }) async {
    final account = gateway.accountId;
    if (account == null) return;
    final epoch = _epoch;
    String? requestId;
    final parameters =
        'provision\n${device.id}\n${target.hardware}\n${build.source}\n${build.artifact}';
    Json? record;
    await action(
      () async {
        provisioningDeviceId = device.id;
        provisioningOutcome = ProvisioningOutcome.pending;
        readback = null;
        readbackDeviceId = null;
        readbackSaved = false;
        if (!provisioningAvailable ||
            !{'Link', 'Core'}.contains(article.role) ||
            build.role != article.role ||
            !device.serial.startsWith('D') ||
            device.ownerId != null ||
            device.state == 'retired' ||
            (device.hardwareUid != null &&
                device.hardwareUid != target.hardware)) {
          throw const ProvisioningFailure(
            'Choose an unclaimed development device, matching product firmware and USB device.',
          );
        }
        _cancelProvisioning = false;
        readback = null;
        readbackDeviceId = null;
        readbackSaved = false;
        _stage('Saving the provisioning attempt…');
        requestId = await journal.reservation(account, parameters, _idFactory);
        _provisionCheckpoint(epoch);
        _stage('Checking operator access and device binding…');
        final backend = gateway as ProvisioningGateway;
        final attempt = await backend.beginProvisioning(
          requestId: requestId!,
          deviceId: device.id,
          hardware: target.hardware,
          build: build,
        );
        _provisionCheckpoint(epoch);
        _checkProvisioningAttempt(
          attempt,
          requestId!,
          device,
          article,
          target,
          build,
        );
        Json report;
        if (attempt['state'] == 'completed') {
          report = _proofReport(attempt['report'] as Json);
        } else {
          if (target.mode == 'bootloader') {
            _stage('Installing firmware. Keep the device connected…');
            await provisioner!.execute(
              account: account,
              command: 'install',
              parameters: {
                'hardware': target.hardware,
                'manifest': build.manifest,
                'volume': target.volume,
              },
            );
            _provisionCheckpoint(epoch);
          }
          _stage('Inspecting identity storage…');
          Future<StoragePreparation> inspect(
            String command,
            Json binding, {
            String? token,
          }) async {
            final result = await provisioner!.execute(
              account: account,
              command: command,
              parameters: {
                ...binding,
                'manifest': build.manifest,
                'inspection_token': ?token,
              },
            );
            _provisionCheckpoint(epoch);
            return StoragePreparation.fromJson(result, binding);
          }

          final preparation = await inspect('inspect-storage', attempt);
          if (preparation.required) {
            if (device.state != 'reserved') {
              throw const ProvisioningFailure(
                'Previously provisioned identity needs diagnosis. Storage preparation is disabled.',
              );
            }
            _stage('Waiting for identity storage preparation confirmation…');
            if (confirmPreparation == null ||
                !await confirmPreparation(preparation)) {
              throw BenchCancelled();
            }
            _provisionCheckpoint(epoch);
            // Approval can remain open while an account/operator grant changes.
            // Reauthorize the exact same request before any destructive command.
            final fresh = await backend.beginProvisioning(
              requestId: requestId!,
              deviceId: device.id,
              hardware: target.hardware,
              build: build,
            );
            _provisionCheckpoint(epoch);
            _checkProvisioningAttempt(
              fresh,
              requestId!,
              device,
              article,
              target,
              build,
            );
            if (fresh['state'] != 'started' || fresh['public_key'] != null) {
              throw const ProvisioningFailure(
                'Identity was registered while waiting. Keep the device and inspect again.',
              );
            }
            _stage('Preparing and verifying identity storage…');
            final prepared = await inspect(
              'prepare-storage',
              fresh,
              token: preparation.token,
            );
            if (prepared.status != 'ready') {
              throw const ProvisioningFailure(
                'Identity storage did not verify ready. Keep the reservation and inspect the saved diagnostic.',
              );
            }
          }
          _stage('Verifying identity and key before and after reboot…');
          // The firmware-owned runner verifies the target/source, reuses any
          // committed key and persists proof checkpoints before returning.
          report = _proofReport(
            await provisioner!.execute(
              account: account,
              command: 'provision',
              parameters: attempt,
            ),
          );
        }
        record = {
          'id': requestId,
          'kind': 'provisioning',
          'device_id': device.id,
          'parameters': parameters,
          'report': report,
        };
        await journal.save(
          account,
          record!,
        ); // Also retain late results after logout/cancel.
        if (epoch != _epoch) return;
        readback = report;
        readbackDeviceId = device.id;
        pendingEvidence = (await journal.pending(account)).length;
        _provisionCheckpoint(epoch);
        _stage('Confirming provisioning with the server…');
        await backend.completeProvisioning(
          requestId: requestId!,
          deviceId: device.id,
          report: report,
        );
      },
      onError: (error) {
        provisioningOutcome = error is BenchCancelled
            ? ProvisioningOutcome.pending
            : ProvisioningOutcome.failed;
      },
      afterRefresh: () async {
        _confirmed(device.id, record!['report'] as Json);
        await journal.synced(account, requestId!);
        await journal.acknowledgeReservation(account, parameters, requestId!);
        if (epoch == _epoch) {
          readbackSaved = true;
          provisioningOutcome = ProvisioningOutcome.successful;
          pendingEvidence = (await journal.pending(account)).length;
        }
      },
    );
  }

  Future<void> syncEvidence() => action(
    () async {
      final epoch = _epoch;
      final account = gateway.accountId!;
      for (final record in await journal.pending(account)) {
        if (epoch != _epoch) return;
        final id = record['id'] as String,
            device = record['device_id'] as String;
        if (record['kind'] == 'provisioning') {
          final report = record['report'] as Json;
          provisioningDeviceId = device;
          provisioningOutcome = ProvisioningOutcome.pending;
          readbackSaved = false;
          _changed();
          await (gateway as ProvisioningGateway).completeProvisioning(
            requestId: id,
            deviceId: device,
            report: report,
          );
          if (epoch != _epoch) return;
          final fresh = await gateway.load();
          if (epoch != _epoch) return;
          registry = fresh;
          _confirmed(device, report);
          await journal.synced(account, id);
          await journal.acknowledgeReservation(
            account,
            record['parameters'] as String,
            id,
          );
          if (epoch == _epoch) {
            readback = report;
            readbackDeviceId = device;
            readbackSaved = true;
            provisioningOutcome = ProvisioningOutcome.successful;
          }
        } else {
          await gateway.recordDiagnostic(
            requestId: id,
            deviceId: device,
            report: record['report'] as Json,
          );
          await journal.synced(account, id);
        }
      }
      if (epoch == _epoch) {
        pendingEvidence = (await journal.pending(account)).length;
      }
    },
    onError: (_) {
      if (provisioningOutcome == ProvisioningOutcome.pending) {
        provisioningOutcome = ProvisioningOutcome.failed;
      }
    },
  );

  Future<void> cancel() async {
    _cancelProvisioning = true;
    try {
      await provisioner?.cancel();
    } finally {
      await runner.cancel();
    }
  }

  Future<void> signOut() async {
    final epoch = ++_epoch;
    access = Access.signedOut;
    _requestedEmail = null;
    _queuedLink = null;
    registry = null;
    readback = null;
    readbackSaved = false;
    pendingEvidence = 0;
    usbInventory = null;
    provisioningStage = null;
    provisioningDeviceId = null;
    provisioningOutcome = null;
    _cancelProvisioning = true;
    busy = true;
    message = null;
    _changed();
    try {
      try {
        try {
          await provisioner?.cancel();
        } finally {
          await runner.cancel();
        }
      } catch (_) {
        /* SDK logout must still run if process cleanup fails. */
      }
      await _signingIn?.future;
      await gateway.signOut();
    } catch (_) {
      /* UI stays signed out. */
    } finally {
      if (epoch == _epoch) {
        busy = false;
        _changed();
      }
    }
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    ++_epoch;
    _closing = _closeResources();
    // Native window teardown is synchronous. Retain the future for callers
    // that can await cleanup; never leak an unhandled asynchronous error.
    unawaited(_closing!.catchError((Object _) {}));
    super.dispose();
  }
}
