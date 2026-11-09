import 'package:supabase/supabase.dart';

import '../domain/registry.dart';
import '../domain/factory_enrollment.dart';
import '../domain/provisioning.dart';
import 'memory_pkce.dart';

/// The desktop has only a publishable key. Authorization stays in checked RPCs.
final class SupabaseGateway
    implements WorkshopGateway, ProvisioningGateway, FactoryGateway {
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
  Future<String> reserve({
    required String requestId,
    required String revisionId,
    required String serialClass,
  }) async {
    return await _rpc('workshop_reserve_device', {
      'p_request_id': requestId,
      'p_revision_id': revisionId,
      'p_serial_class': serialClass,
    }) as String;
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
  Future<Json> beginProvisioning({
    required String requestId,
    required String deviceId,
    required String hardware,
    required FirmwareBuild build,
  }) async => Map<String, dynamic>.from(
    await _rpc('workshop_begin_provisioning', {
      'p_request_id': requestId,
      'p_device_id': deviceId,
      'p_hardware': hardware,
      'p_source': build.source,
      'p_artifact': build.artifact,
      'p_version': build.version,
    }) as Map,
  );

  @override
  Future<void> completeProvisioning({
    required String requestId,
    required String deviceId,
    required Json report,
  }) async {
    final session = _client.auth.currentSession;
    if (session == null) throw SessionExpired();
    try {
      final response = await _client.functions
          .invoke(
            'workshop-provisioning',
            headers: {'Authorization': 'Bearer ${session.accessToken}'},
            body: {
              'request_id': requestId,
              'before': report['before'],
              'after': report['after'],
            },
          )
          .timeout(const Duration(seconds: 30));
      final data = response.data;
      if (response.status != 200 ||
          data is! Map ||
          data['version'] != 1 ||
          data['ok'] != true ||
          data['device_id'] != deviceId ||
          accountId != session.user.id) {
        throw const ProvisioningFailure(
          'Registry confirmation was not verified. Your proof is retained; retry its upload.',
        );
      }
    } on FunctionException catch (error) {
      if (error.status == 401) throw SessionExpired();
      if (error.status == 403) throw OperatorDenied();
      throw const ProvisioningFailure(
        'Registry confirmation failed. Your proof is retained; retry its upload when the server verifier is available.',
      );
    }
  }

  bool _sameSession(Session session) =>
      _client.auth.currentSession?.accessToken == session.accessToken &&
      accountId == session.user.id;

  @override
  Future<Json> factoryStatus(String deviceId) async {
    final session = _client.auth.currentSession;
    if (session == null) throw SessionExpired();
    final data = await _rpc('workshop_factory_enrollment', {
      'p_device_id': deviceId,
    });
    if (!_sameSession(session) || data is! Map) throw const FactoryFailure();
    return Map<String, dynamic>.from(data);
  }

  Future<Json> _factory(Json body) async {
    final session = _client.auth.currentSession;
    if (session == null) throw SessionExpired();
    try {
      final response = await _client.functions
          .invoke(
            'workshop-factory',
            headers: {'Authorization': 'Bearer ${session.accessToken}'},
            body: body,
          )
          .timeout(const Duration(seconds: 30));
      final data = response.data;
      if (!_sameSession(session) ||
          response.status != 200 ||
          data is! Map ||
          data['v'] != 1 ||
          data['ok'] != true) {
        throw const FactoryFailure();
      }
      return Map<String, dynamic>.from(data);
    } on FunctionException catch (error) {
      if (error.status == 401) throw SessionExpired();
      // C5.2 deliberately uses a generic denial for authorization/provider faults.
      // A403 cannot be interpreted as proof that the whole operator was revoked.
      throw const FactoryFailure();
    }
  }

  @override
  Future<Json> issueFactory({
    required String requestId,
    required String provisioningRequestId,
    required String deviceId,
    required String role,
  }) async {
    final result = await _factory({
      'action': 'issue',
      'request_id': requestId,
      'provisioning_request_id': provisioningRequestId,
    });
    final data = result['enrollment'];
    if (data is! Map ||
        data['v'] != 1 ||
        data['device_id'] != deviceId ||
        data['environment'] != 'development' ||
        data['role'] != role ||
        data['state'] != 'ready' ||
        data['head_revision'] is! int ||
        (data['head_revision'] as int) < 1 ||
        (data['head_revision'] as int) > 4294967295 ||
        data['public_key_sha256'] is! String ||
        !hexId(data['public_key_sha256'] as String, 64)) {
      throw const FactoryFailure();
    }
    return Map<String, dynamic>.from(data);
  }

  @override
  Future<String> revealFactory({
    required String requestId,
    required String deviceId,
  }) async {
    final result = await _factory({
      'action': 'reveal',
      'request_id': requestId,
      'device_id': deviceId,
    });
    final text = result['private_claim_qr'];
    if (text is! String || text.length != 145) throw const FactoryFailure();
    return text;
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
