import 'registry.dart';

final class BenchCancelled implements Exception {}

abstract interface class BenchRunner {
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  });
  Future<void> cancel();
}

abstract interface class EvidenceStore {
  Future<String> reservation(
    String account,
    String parameters,
    String Function() createId,
  );
  Future<void> acknowledgeReservation(
    String account,
    String parameters,
    String expectedId,
  );
  Future<void> save(String account, Json record);
  Future<List<Json>> pending(String account);
  Future<void> synced(String account, String id);
}
