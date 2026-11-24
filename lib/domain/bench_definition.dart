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
  static const asset = 'assets/bench/provisioned-identity.v2.json';
  static const legacyAsset = 'assets/bench/provisioned-identity.v1.json';
  static const inspectionAsset = 'assets/bench/credential-inspection.v1.json';
  static const readinessAsset = 'assets/bench/credential-readiness.v2.json';
  static const legacyReadinessAsset =
      'assets/bench/credential-readiness.v1.json';
  static const deliveryAsset = 'assets/bench/credential-delivery.v1.json';
  static const installationAsset =
      'assets/bench/credential-installation.v2.json';
  static const intentStopAsset = 'assets/bench/credential-intent-stop.v2.json';
  static const preparationAsset = 'assets/bench/credential-preparation.v2.json';
  static const legacyDigest =
      '81bbd6890809bb4ffa8c9ee283d7003c5f3cf2404a8b21fdc56d3d2e39220356';
  static const digest =
      '770caed1b53288ac327900b50930e3555ed0a3d9068e2e2b61ab3441e3a9da1b';
  static const inspectionDigest =
      'f49a91ec168090155f258c3a04636580cfa5f3fc7fbeb9f90949f203c92f48b4';

  static const readinessDigest =
      'd74c1e354ebdde8789c1c20edb2f5b9b3c10e18747bd2020e1b1625c6b326eff';
  static const deliveryDigest =
      '862ff3465ff13721a7976afcd11d9fe2d6ca9cb21775a21572d9365eca71dc9d';

  static const installationDigest =
      '3d9ae1f7803f294431922ba559ffc65ad9013d8456b4d5b67a9a832757f57e1d';
  static const intentStopDigest =
      '5d07f3e795e4858d44991db91429e69f45d4cfbc09bfed10418e669245e5b813';
  static const preparationDigest =
      '072e00b2d37e1ae0330f928a077b5069e83decea6f12ff581963096910332a76';
  static const readinessV2Digest =
      'abc1bc246be4dbeb57635f804eaac876f4cc3095b917c477ec43beb47ba738ca';
  static const installationV2Digest =
      'b7ab4f4539822f7ce1a6d357730f228a9fb47754a19ec9c75c9d026db1fd6b8e';
  static const intentStopV2Digest =
      'af1804d8c29914dc4a2ef5d7c14eeb9348667bfecd55bda372696842f77870a9';
  static const preparationV2Digest =
      'eae38c388ceded16f59ad693f9fd201ec32cc7966c09ab67eb6d342e85a467e1';

  BenchDefinition.fromSnapshot(this.snapshot)
    : snapshotDigest = sha256.convert(utf8.encode(snapshot)).toString() {
    if (snapshotDigest != digest &&
        snapshotDigest != legacyDigest &&
        snapshotDigest != inspectionDigest &&
        snapshotDigest != readinessDigest &&
        snapshotDigest != deliveryDigest &&
        snapshotDigest != installationDigest &&
        snapshotDigest != intentStopDigest &&
        snapshotDigest != preparationDigest &&
        snapshotDigest != readinessV2Digest &&
        snapshotDigest != installationV2Digest &&
        snapshotDigest != intentStopV2Digest &&
        snapshotDigest != preparationV2Digest) {
      throw const FormatException(
        'Unknown bench definition revision or digest',
      );
    }
  }

  final String snapshot;
  final String snapshotDigest;
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
      if (pins['additional_files'] != null)
        ...(pins['additional_files'] as Map).cast<String, String>(),
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

  Json inspectionParameters(String publicKey) => {
    ...parameters,
    'artifact': build.artifact,
    'public_key': publicKey,
    'device_id': device.id,
    'serial': device.serial,
    'article_id': article.articleId,
    'article_revision_id': article.id,
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
