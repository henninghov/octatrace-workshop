import 'registry.dart';

enum FirmwareHostSuite {
  tooling,
  host,
  authorityStorage,
  claimQr,
  deviceAuthority,
  deviceCredential,
  fieldHandshake,
  proofContext,
  setupTransfer,
  sessionControl,
  authorityResources,
  fieldResources,
  authorityLayout,
}

/// Host qualification is independent of the device and UI adapters.
abstract interface class FirmwareChecks {
  Future<Json> run({
    required String account,
    required FirmwareHostSuite suite,
    required String firmwareRoot,
    required String python,
    required String fonts,
  });
  Future<List<Json>> history({required String account, required String python});
  Future<String> export({
    required String account,
    required String python,
    required String attempt,
    required String directory,
  });
  Future<void> cancel();
}
