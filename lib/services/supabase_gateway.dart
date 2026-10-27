import 'package:supabase/supabase.dart';

import '../domain/registry.dart';
import 'memory_pkce.dart';

/// The desktop has only a publishable key. Authorization stays in checked RPCs.
final class SupabaseGateway implements WorkshopGateway {
  factory SupabaseGateway(String url, String key) {
    final pkce = MemoryPkce();
    return SupabaseGateway.withClient(
      SupabaseClient(
        url,
        key,
        authOptions: AuthClientOptions(pkceAsyncStorage: pkce),
      ),
      pkce,
    );
  }
  SupabaseGateway.withClient(this._client, this._pkce);
  final MemoryPkce _pkce;
  final SupabaseClient _client;
  @override
  String? get accountId => _client.auth.currentUser?.id;

  @override
  String? get accountEmail => _client.auth.currentUser?.email;
  @override
  Future<void> requestLink(String email) async {
    _pkce.clear();
    await _client.auth.signInWithOtp(
      email: email,
      emailRedirectTo: workshopCallback,
      shouldCreateUser: false,
    );
  }

  @override
  Future<void> exchangeLink(String code) async {
    final response = await _client.auth.exchangeCodeForSession(code);
    if (response.session.user.emailConfirmedAt == null) throw SessionExpired();
  }

  Future<dynamic> _rpc(String name, [Json? params]) async {
    final session = _client.auth.currentSession;
    if (session == null) throw SessionExpired();
    try {
      // Bind this request to its initiating account, even if auth changes while
      // the SDK awaits token refresh or dispatches the HTTP request.
      return await _client
          .rpc(name, params: params)
          .setHeader('Authorization', 'Bearer ${session.accessToken}')
          .retry(enabled: false, requestTimeout: const Duration(seconds: 30));
    } on PostgrestException catch (e) {
      if (e.code == '42501') throw OperatorDenied();
      if (e.code == 'PGRST301' || e.code == 'PGRST303') throw SessionExpired();
      rethrow;
    }
  }

  @override
  Future<void> authorizeOperator() async {
    final account = accountId;
    final result = await _rpc('workshop_authorize');
    if (result is! Map ||
        result['operator_user_id'] != account ||
        accountId != account) {
      throw OperatorDenied();
    }
  }

  @override
  Future<Registry> load() async => Registry.fromJson(
    Map<String, dynamic>.from(await _rpc('workshop_overview') as Map),
  );

  @override
  Future<void> createArticle({
    required String code,
    required String name,
    required String role,
    required String caseVersion,
    required List<Json> parts,
  }) async {
    await _rpc('workshop_create_article', {
      'p_code': code,
      'p_name': name,
      'p_role': role,
      'p_case_version': caseVersion,
      'p_parts': parts,
    });
  }

  @override
  Future<void> addRevision({
    required String articleId,
    required String caseVersion,
    required List<Json> parts,
  }) async {
    await _rpc('workshop_add_revision', {
      'p_article_id': articleId,
      'p_case_version': caseVersion,
      'p_parts': parts,
    });
  }

  @override
  Future<void> reserve({
    required String requestId,
    required String revisionId,
    required String serialClass,
  }) async {
    await _rpc('workshop_reserve_device', {
      'p_request_id': requestId,
      'p_revision_id': revisionId,
      'p_serial_class': serialClass,
    });
  }

  @override
  Future<void> recordDiagnostic({
    required String requestId,
    required String deviceId,
    required Json report,
  }) async {
    await _rpc('workshop_record_diagnostic', {
      'p_request_id': requestId,
      'p_device_id': deviceId,
      'p_report': report,
    });
  }

  @override
  Future<void> signOut() async {
    try {
      await _client.auth.signOut(scope: SignOutScope.local);
    } finally {
      _pkce.clear();
    }
  }

  @override
  Future<void> dispose() async => _client.dispose();
}
