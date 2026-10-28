import 'registry.dart';

enum ProvisioningOutcome { pending, successful, failed }

bool hexId(String value, int width) =>
    RegExp('^[0-9a-f]{$width}\$').hasMatch(value) && value != '0' * width;

final class UsbTarget {
  UsbTarget.fromJson(Json json)
    : hardware = json['hardware'] as String,
      mode = json['mode'] as String,
      label = json['label'] as String,
      volume = json['volume'] as String? {
    if (!hexId(hardware, 16) ||
        !{'app', 'bootloader'}.contains(mode) ||
        (mode == 'bootloader' &&
            (volume == null || !volume!.startsWith('/Volumes/')))) {
      throw const FormatException('Invalid USB target');
    }
  }
  final String hardware, mode, label;
  final String? volume;
  String get key => '$hardware/$mode';
}

final class FirmwareBuild {
  FirmwareBuild.fromJson(Json json)
    : role = json['role'] as String? ?? 'Link',
      source = json['source'] as String,
      artifact = json['artifact'] as String,
      version = json['version'] as String,
      manifest = json['manifest'] as String,
      label = json['label'] as String {
    if (!{'Link', 'Core'}.contains(role) ||
        !hexId(source, 64) ||
        !hexId(artifact, 64) ||
        !RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(version)) {
      throw const FormatException('Invalid firmware build');
    }
  }
  final String role, source, artifact, version, manifest, label;
  String get key => '$role/$source';
}

final class UsbInventory {
  UsbInventory.fromJson(Json json)
    : targets = (json['targets'] as List)
          .map((j) => UsbTarget.fromJson(j as Json))
          .toList(),
      builds = (json['builds'] as List)
          .map((j) => FirmwareBuild.fromJson(j as Json))
          .toList() {
    if (targets.map((t) => t.key).toSet().length != targets.length ||
        builds.map((b) => b.key).toSet().length != builds.length) {
      throw const FormatException('Ambiguous USB inventory');
    }
  }
  final List<UsbTarget> targets;
  final List<FirmwareBuild> builds;
}

/// Public, attempt-bound preparation context. Board erase policy belongs to Python.
final class StoragePreparation {
  StoragePreparation.fromJson(Json data, Json attempt)
    : status = data['status'] as String,
      profile = data['profile'] as Json,
      serial = data['serial'] as String,
      token = data['inspection_token'] as String? {
    if (!{'ready', 'preserved', 'required'}.contains(status) ||
        !hexId(data['boot'] as String, 32) ||
        data['role'] != (attempt['role'] ?? 'Link') ||
        [
          'request_id',
          'device_id',
          'serial',
          'article_id',
          'article_revision_id',
          'hardware',
          'source',
          'artifact',
        ].any((key) => data[key] != attempt[key]) ||
        profile['id'] is! String ||
        (profile['id'] as String).isEmpty ||
        profile['name'] is! String ||
        (profile['name'] as String).isEmpty ||
        profile['bytes'] is! int ||
        (profile['bytes'] as int) <= 0 ||
        (required && (token == null || !hexId(token!, 64)))) {
      throw const FormatException('Invalid storage preparation context');
    }
  }
  final String status, serial;
  final Json profile;
  final String? token;
  bool get required => status == 'required';
  String get boardName => profile['name'] as String;
  int get bytes => profile['bytes'] as int;
}

abstract interface class ProvisioningRunner {
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  });
  Future<void> cancel();
}

abstract interface class ProvisioningGateway {
  Future<Json> beginProvisioning({
    required String requestId,
    required String deviceId,
    required String hardware,
    required FirmwareBuild build,
  });
  Future<void> completeProvisioning({
    required String requestId,
    required String deviceId,
    required Json report,
  });
}

final class ProvisioningFailure implements Exception {
  const ProvisioningFailure(this.message);
  final String message;
}
