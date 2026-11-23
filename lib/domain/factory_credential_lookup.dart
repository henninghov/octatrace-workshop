import 'package:crypto/crypto.dart';

import 'factory_enrollment.dart';
import 'registry.dart';

/// The credential is public, but retrieval still requires an active operator.
/// Bind its issuance record to the independently verified device public key.
final class FactoryCredentialLookup {
  const FactoryCredentialLookup(this.gateway);
  final FactoryGateway gateway;

  Future<PublicFactoryCredential> find(
    DeviceRecord device,
    ArticleRevision article,
    String publicKey,
  ) async {
    if (device.state != 'provisioned' ||
        device.revisionId != article.id ||
        !{'Link', 'Core'}.contains(article.role) ||
        !RegExp(r'^04[0-9a-f]{128}$').hasMatch(publicKey)) {
      throw const FormatException('Factory credential identity is unavailable');
    }
    final status = FactoryStatus.fromJson(
      await gateway.factoryStatus(device.id),
      deviceId: device.id,
      role: article.role,
    );
    final publicBytes = <int>[
      for (var i = 0; i < publicKey.length; i += 2)
        int.parse(publicKey.substring(i, i + 2), radix: 16),
    ];
    if (!status.ready ||
        status.credentialSha256 == null ||
        sha256.convert(publicBytes).toString() != status.publicKeySha256) {
      throw const FormatException('Factory credential identity is unavailable');
    }
    return gateway.publicCredential(
      deviceId: device.id,
      role: article.role,
      expectedDigest: status.credentialSha256!,
    );
  }
}
