import 'package:flutter/foundation.dart';

import 'factory_enrollment.dart';
import 'ports.dart';
import 'registry.dart';

/// Per-view, per-account private state. Nothing private is written to the journal.
final class FactoryController extends ChangeNotifier {
  FactoryController(
    this.gateway,
    this.journal, {
    required this.account,
    required this.device,
    required this.role,
    required this.isCurrent,
    required this.createId,
  });
  final FactoryGateway gateway;
  final EvidenceStore journal;
  final String account, role;
  final DeviceRecord device;
  final bool Function() isCurrent;
  final String Function() createId;
  int _generation = 0;
  bool _disposed = false, busy = false;
  FactoryStatus? status;
  PrivateClaimQr? privateQr;
  String? message;
  bool get eligible =>
      device.serial.startsWith('D') &&
      device.state == 'provisioned' &&
      {'Link', 'Core'}.contains(role);
  bool get canIssue =>
      eligible && device.ownerId == null && status != null && !status!.ready;
  bool get canReveal => eligible && status?.ready == true;
  bool _current(int generation) =>
      !_disposed && generation == _generation && isCurrent();
  void _notify() {
    if (!_disposed) notifyListeners();
  }

  void hide({String? explanation}) {
    ++_generation;
    privateQr = null;
    busy = false;
    message = explanation;
    _notify();
  }

  Future<void> _run(Future<void> Function(int) operation) async {
    if (_disposed || busy || !isCurrent()) return;
    final generation = ++_generation;
    privateQr = null;
    message = null;
    busy = true;
    _notify();
    try {
      await operation(generation);
    } catch (error) {
      if (_current(generation)) {
        message = error is SessionExpired || error is OperatorDenied
            ? 'Sign in again to check your current operator access.'
            : 'Could not complete this request. Check your connection and server setup. Private QR reveal also requires sign-in within 15 minutes; you can sign in again below.';
      }
    } finally {
      if (_current(generation)) {
        busy = false;
        _notify();
      }
    }
  }

  Future<void> refresh() => _run((generation) async {
    status = null;
    final data = await gateway.factoryStatus(device.id);
    if (_current(generation)) {
      status = FactoryStatus.fromJson(data, deviceId: device.id, role: role);
    }
  });
  Future<void> issue(String proofId) => _run((generation) async {
    if (!canIssue || !factoryUuid(proofId)) throw const FactoryFailure();
    final parameters = 'factory-credential\n${device.id}\n$proofId';
    final request = await journal.reservation(account, parameters, createId);
    if (!_current(generation)) return;
    final data = await gateway.issueFactory(
      requestId: request,
      provisioningRequestId: proofId,
      deviceId: device.id,
      role: role,
    );
    if (!_current(generation)) return;
    final result = FactoryStatus.fromJson(
      await gateway.factoryStatus(device.id),
      deviceId: device.id,
      role: role,
    );
    if (!_current(generation)) return;
    if (!result.ready || result.publicKeySha256 != data['public_key_sha256']) {
      throw const FactoryFailure();
    }
    await journal.acknowledgeReservation(account, parameters, request);
    if (_current(generation)) {
      status = result;
      message =
          'Factory credential issued. The original private claim QR is ready.';
    }
  });
  Future<void> reveal() => _run((generation) async {
    if (!canReveal) throw const FactoryFailure();
    final text = await gateway.revealFactory(
      requestId: createId(),
      deviceId: device.id,
    );
    if (!_current(generation)) return;
    privateQr = PrivateClaimQr.parse(
      text,
      deviceId: device.id,
      role: role,
      publicKeySha256: status!.publicKeySha256!,
    );
  });
  @override
  void dispose() {
    _disposed = true;
    ++_generation;
    privateQr = null;
    super.dispose();
  }
}
