import 'package:supabase/supabase.dart';

/// Pending login proof stays in this process. Restart requires a fresh link.
final class MemoryPkce extends GotrueAsyncStorage {
  final _values = <String, String>{};
  @override
  Future<String?> getItem({required String key}) async => _values[key];
  @override
  Future<void> setItem({required String key, required String value}) async {
    _values[key] = value;
  }

  @override
  Future<void> removeItem({required String key}) async {
    _values.remove(key);
  }

  void clear() => _values.clear();
}
