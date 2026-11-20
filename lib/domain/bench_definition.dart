import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'provisioning.dart';
import 'registry.dart';

typedef BenchBuild = ({
  String role,
  String version,
  String source,
  String artifact,
});

/// Catalog text is display data. Only locally reviewed bytes can bind a runner.
final class BenchDefinition {
  static const asset = 'assets/bench/provisioned-identity.v1.json';
  static const digest =
      '81bbd6890809bb4ffa8c9ee283d7003c5f3cf2404a8b21fdc56d3d2e39220356';

  BenchDefinition.fromSnapshot(this.snapshot) {
    if (sha256.convert(utf8.encode(snapshot)).toString() != digest) {
      throw const FormatException(
        'Unknown bench definition revision or digest',
      );
    }
  }

  final String snapshot;
  // Return a new view so edits by a caller cannot change the reviewed snapshot.
  Json get guide => jsonDecode(snapshot) as Json;

  List<BenchBuild> get builds => [
    for (final b in guide['builds'] as List)
      (
        role: b['role'] as String,
        version: b['version'] as String,
        source: b['source'] as String,
        artifact: b['artifact'] as String,
      ),
  ];

  Map<String, String> get runnerFiles {
    final pins = guide['runner'] as Json;
    return {
      'tools/provision.py': pins['source_sha256'] as String,
      'tools/bench.py': pins['transport_sha256'] as String,
      'tools/provision_platform.py': pins['discovery_sha256'] as String,
      'usb-provisioning.lock.json': pins['usb_lock_sha256'] as String,
      'control-storage.lock.json': pins['control_lock_sha256'] as String,
    };
  }

  ProvisionedIdentityRead admit({
    required DeviceRecord device,
    required ArticleRevision article,
    required UsbTarget target,
    required BenchBuild build,
  }) {
    if (device.state != 'provisioned' ||
        device.revisionId != article.id ||
        device.hardwareUid != target.hardware ||
        target.mode != 'app' ||
        article.role != build.role ||
        !builds.contains(build)) {
      throw const ProvisioningFailure(
        'Blocked: device, USB target or build differs from the identity procedure.',
      );
    }
    return ProvisionedIdentityRead._(this, device, article, build);
  }
}

final class ProvisionedIdentityRead {
  const ProvisionedIdentityRead._(
    this.definition,
    this.device,
    this.article,
    this.build,
  );
  final BenchDefinition definition;
  final DeviceRecord device;
  final ArticleRevision article;
  final BenchBuild build;

  Json get parameters => {
    'hardware': device.hardwareUid,
    'source': build.source,
    'role': build.role,
  };

  /// Python already validated the frame and bound the hardware, role and source.
  /// A valid P1 frame may describe an empty board or another registry record.
  void checkRegistryIdentity(Json frame) {
    if (frame['state'] != 'ready' ||
        frame['busy'] != false ||
        frame['failed'] != false ||
        frame['device_id'] != device.id ||
        frame['serial'] != device.serial ||
        frame['article_id'] != article.articleId ||
        frame['article_revision_id'] != article.id) {
      throw const ProvisioningFailure(
        'Identity read did not confirm the selected provisioned record.',
      );
    }
  }
}
