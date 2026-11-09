import 'dart:convert';

import 'registry.dart';

bool factoryUuid(Object? value) =>
    value is String &&
    RegExp(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    ).hasMatch(value);
bool _digest(Object? value) =>
    value is String &&
    RegExp(r'^[0-9a-f]{64}$').hasMatch(value) &&
    value != '0' * 64;

final class FactoryStatus {
  FactoryStatus.fromJson(
    Json data, {
    required String deviceId,
    required String role,
  }) : state = data['state'] as String,
       publicKeySha256 = data['public_key_sha256'] as String? {
    if (data['v'] != 1 ||
        data['device_id'] != deviceId ||
        !factoryUuid(deviceId) ||
        !{'not_enrolled', 'pending', 'ready'}.contains(state) ||
        !{'Link', 'Core'}.contains(role)) {
      throw const FormatException('Invalid factory status');
    }
    if (state != 'not_enrolled' &&
        (data['environment'] != 'development' ||
            data['role'] != role ||
            !factoryUuid(data['enrollment_id']) ||
            !_digest(publicKeySha256) ||
            (ready && !_digest(data['credential_sha256'])) ||
            (!ready && data['credential_sha256'] != null))) {
      throw const FormatException('Factory identity does not match');
    }
  }
  final String state;
  final String? publicKeySha256;
  bool get ready => state == 'ready';
}

/// Only the exact, bounded C4.1 structure is accepted. Parsing is not claiming
/// or proof of ownership: the authenticated backend grants private reveal.
final class PrivateClaimQr {
  PrivateClaimQr._(this.text);
  factory PrivateClaimQr.parse(
    String text, {
    required String deviceId,
    required String role,
    required String publicKeySha256,
    String environment = 'development',
  }) {
    const prefix = 'OCTATRACE-CLAIM-1:';
    if (!{'development', 'production'}.contains(environment) ||
        text.length != 145 ||
        !text.startsWith(prefix) ||
        !RegExp(r'^[A-Za-z0-9_-]{127}$')
            .hasMatch(text.substring(prefix.length))) {
      throw const FormatException('Invalid private claim QR');
    }
    final raw = text.substring(prefix.length),
        bytes = base64Url.decode(base64Url.normalize(raw));
    final fixed = {
      0: 0xa6,
      1: 1,
      2: 1,
      3: 2,
      4: environment == 'development' ? 1 : 2,
      5: 3,
      7: 4,
      8: 0x50,
      25: 5,
      26: 0x58,
      27: 0x20,
      60: 6,
      61: 0x58,
      62: 0x20,
    };
    if (bytes.length != 95 ||
        base64Url.encode(bytes).replaceAll('=', '') != raw ||
        fixed.entries.any((e) => bytes[e.key] != e.value) ||
        bytes[6] != (role == 'Link' ? 1 : 2) ||
        !{'Link', 'Core'}.contains(role)) {
      throw const FormatException('Invalid private claim QR');
    }
    String hex(Iterable<int> value) =>
        value.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
    final id = hex(bytes.sublist(9, 25));
    final uuid =
        '${id.substring(0, 8)}-${id.substring(8, 12)}-${id.substring(12, 16)}-${id.substring(16, 20)}-${id.substring(20)}';
    if (!factoryUuid(uuid) ||
        uuid != deviceId ||
        !_digest(publicKeySha256) ||
        hex(bytes.sublist(28, 60)) != publicKeySha256 ||
        !bytes.sublist(63).any((x) => x != 0)) {
      throw const FormatException('Private claim QR identity does not match');
    }
    return PrivateClaimQr._(text);
  }
  final String text;
  @override
  String toString() => '[Private claim QR]';
}

abstract interface class FactoryGateway {
  Future<Json> factoryStatus(String deviceId);
  Future<Json> issueFactory({
    required String requestId,
    required String provisioningRequestId,
    required String deviceId,
    required String role,
  });
  Future<String> revealFactory({
    required String requestId,
    required String deviceId,
  });
}

final class FactoryFailure implements Exception {
  const FactoryFailure();
  @override
  String toString() => 'Factory operation unavailable';
}
