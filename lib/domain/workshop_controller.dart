import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';

import 'ports.dart';
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
    String Function()? idFactory,
    DateTime Function()? now,
  }) : _idFactory = idFactory ?? newRequestId,
       _now = now ?? DateTime.now;
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
  int _epoch = 0;
  bool _disposed = false;
  Completer<void>? _signingIn;
  String? _requestedEmail;
  Uri? _queuedLink;
  Future<void>? _closing;
  Future<void> get closed => _closing ?? Future<void>.value();

  Future<void> _closeResources() async {
    try {
      await runner.cancel();
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
  }) async {
    if (busy || access != Access.ready) return;
    final epoch = _epoch;
    busy = true;
    message = null;
    _changed();
    try {
      await operation();
      if (epoch != _epoch) return;
      final data = await gateway.load();
      if (epoch == _epoch) {
        registry = data;
        if (afterRefresh != null) await afterRefresh();
      }
    } catch (error) {
      if (epoch != _epoch) return;
      if (error is OperatorDenied || error is SessionExpired) {
        registry = null;
        readback = null;
        access = Access.denied;
        message = 'Operator access is no longer available. Sign in again.';
      } else {
        message = 'Operation could not be completed. Your existing records are retained; retry when ready.';
      }
    } finally {
      if (epoch == _epoch) {
        busy = false;
        _changed();
      }
    }
  }

  Future<void> refresh() => action(() async {});

  Future<void> reserve(String revision, String serialClass) async {
    final parameters = '$revision\n$serialClass';
    final epoch = _epoch;
    final account = gateway.accountId;
    if (account == null) return;
    String? requestId;
    await action(
      () async {
        requestId = await journal.reservation(account, parameters, _idFactory);
        if (epoch != _epoch) return;
        await gateway.reserve(
          requestId: requestId!,
          revisionId: revision,
          serialClass: serialClass,
        );
      },
      afterRefresh: () =>
          journal.acknowledgeReservation(account, parameters, requestId!),
    );
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

  Future<void> syncEvidence() => action(() async {
    final epoch = _epoch;
    final account = gateway.accountId!;
    for (final record in await journal.pending(account)) {
      if (epoch != _epoch) return;
      await gateway.recordDiagnostic(
        requestId: record['id'] as String,
        deviceId: record['device_id'] as String,
        report: record['report'] as Json,
      );
      await journal.synced(account, record['id'] as String);
    }
    if (epoch == _epoch) {
      pendingEvidence = (await journal.pending(account)).length;
    }
  });

  Future<void> cancel() async {
    await runner.cancel();
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
    busy = true;
    message = null;
    _changed();
    try {
      try {
        await runner.cancel();
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
