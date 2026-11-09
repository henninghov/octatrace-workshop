import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:supabase/supabase.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/memory_pkce.dart';
import 'package:octatrace_workshop/services/supabase_gateway.dart';

import 'factory_fixtures.dart' as f;

void main() {
  late SupabaseGateway gateway;
  late List<http.Request> requests;
  late int status, sessionNumber;
  dynamic reply;
  Completer<http.Response>? held;
  setUp(() {
    requests = [];
    status = 200;
    sessionNumber = 0;
    reply = null;
    held = null;
    final pkce = MemoryPkce();
    gateway = SupabaseGateway.withClient(
      SupabaseClient(
        'https://example.invalid',
        'synthetic-publishable',
        authOptions: AuthClientOptions(
          autoRefreshToken: false,
          pkceAsyncStorage: pkce,
        ),
        httpClient: MockClient((r) async {
          requests.add(r);
          if (r.url.path.endsWith('/token')) {
            return http.Response(
              jsonEncode({
                'access_token': 'synthetic-access-${++sessionNumber}',
                'refresh_token': 'synthetic-refresh',
                'token_type': 'bearer',
                'expires_in': 3600,
                'user': {
                  'id': f.account,
                  'aud': 'authenticated',
                  'role': 'authenticated',
                  'email': 'operator@example.invalid',
                  'email_confirmed_at': '2026-11-09T00:00:00Z',
                  'created_at': '2026-11-09T00:00:00Z',
                  'app_metadata': {},
                  'user_metadata': {},
                },
              }),
              200,
              headers: {'content-type': 'application/json'},
              request: r,
            );
          }
          if (held != null &&
              !r.url.path.contains('/otp') &&
              !r.url.path.contains('/logout')) {
            return held!.future;
          }
          return http.Response(
            jsonEncode(reply ?? {}),
            status,
            headers: {'content-type': 'application/json'},
            request: r,
          );
        }),
      ),
      pkce,
    );
  });
  tearDown(() async {
    await gateway.dispose();
  });
  Future<void> login() async {
    await gateway.requestLink('operator@example.invalid');
    await gateway.exchangeLink('synthetic');
  }

  Future<Json> issue() => gateway.issueFactory(
    requestId: f.request,
    provisioningRequestId: f.proof,
    deviceId: f.unit().id,
    role: 'Link',
  );
  Future<String> reveal() =>
      gateway.revealFactory(requestId: f.request, deviceId: f.unit().id);
  Json issued() => {
    'v': 1,
    'ok': true,
    'enrollment': {
      'v': 1,
      'device_id': f.unit().id,
      'environment': 'development',
      'role': 'Link',
      'state': 'ready',
      'head_revision': 1,
      'public_key_sha256': f.qrFields()['public_key_sha256'],
    },
  };
  test('status and actions use only user-authenticated RPC/Edge ports and exact request bindings', () async {
    await login();
    reply = f.status('ready');
    expect(await gateway.factoryStatus(f.unit().id), reply);
    expect(requests.last.url.path, '/rest/v1/rpc/workshop_factory_enrollment');
    expect(jsonDecode(requests.last.body), {'p_device_id': f.unit().id});
    reply = issued();
    await issue();
    expect(requests.last.url.path, '/functions/v1/workshop-factory');
    expect(requests.last.headers['Authorization'], 'Bearer synthetic-access-1');
    expect(jsonDecode(requests.last.body), {
      'action': 'issue',
      'request_id': f.request,
      'provisioning_request_id': f.proof,
    });
    reply = {'v': 1, 'ok': true, 'private_claim_qr': f.qrRow()['text']};
    expect(await reveal(), f.qrRow()['text']);
    expect(jsonDecode(requests.last.body), {
      'action': 'reveal',
      'request_id': f.request,
      'device_id': f.unit().id,
    });
    expect(
      requests.any(
        (r) =>
            r.url.path.contains('key_material') ||
            r.url.path.contains('complete_factory') ||
            r.url.path.contains('reserve_qr'),
      ),
      isFalse,
    );
  });
  test('missing session and HTTP denial/provider faults cannot return private data', () async {
    await expectLater(
      gateway.factoryStatus(f.unit().id),
      throwsA(isA<SessionExpired>()),
    );
    await expectLater(issue(), throwsA(isA<SessionExpired>()));
    await login();
    for (final code in [401, 403, 404, 500]) {
      status = code;
      reply = {'error': 'sensitive internal diagnostic'};
      await expectLater(
        reveal(),
        throwsA(code == 401 ? isA<SessionExpired>() : isA<FactoryFailure>()),
      );
    }
  });
  test('strict issue response rejects wrong identity, version, scope, digest and head revision', () async {
    await login();
    for (final change in [
      {'v': 2},
      {'device_id': f.account},
      {'environment': 'production'},
      {'role': 'Core'},
      {'state': 'pending'},
      {'head_revision': null},
      {'head_revision': 0},
      {'head_revision': 4294967296},
      {'public_key_sha256': null},
      {'public_key_sha256': '00' * 32},
    ]) {
      reply = issued();
      (reply['enrollment'] as Json).addAll(change);
      await expectLater(issue(), throwsA(isA<FactoryFailure>()));
    }
    for (final result in [
      null,
      [],
      {'v': 2, 'ok': true},
      {'v': 1, 'ok': false},
      {'v': 1, 'ok': true, 'enrollment': []},
    ]) {
      reply = result ?? {'v': 0};
      await expectLater(issue(), throwsA(isA<FactoryFailure>()));
    }
    status = 201;
    reply = issued();
    await expectLater(issue(), throwsA(isA<FactoryFailure>()));
  });
  test('malformed raw payload, status and late result after same-account replacement are rejected', () async {
    await login();
    reply = [];
    await expectLater(
      gateway.factoryStatus(f.unit().id),
      throwsA(isA<FactoryFailure>()),
    );
    for (final value in [null, 1, 'bad']) {
      reply = {'v': 1, 'ok': true, 'private_claim_qr': value};
      await expectLater(reveal(), throwsA(isA<FactoryFailure>()));
    }
    held = Completer();
    final future = reveal();
    final check = expectLater(future, throwsA(isA<FactoryFailure>()));
    while (!requests.any((r) => r.url.path.contains('/functions/'))) {
      await Future<void>.delayed(Duration.zero);
    }
    // Let this dispatch before replacing its session; same user ID is insufficient.
    await Future<void>.delayed(Duration.zero);
    await login();
    held!.complete(
      http.Response(
        jsonEncode({'v': 1, 'ok': true, 'private_claim_qr': f.qrRow()['text']}),
        200,
        headers: {'content-type': 'application/json'},
        request: requests.last,
      ),
    );
    await check;
  });
  test('late status after logout is not accepted', () async {
    await login();
    held = Completer();
    final future = gateway.factoryStatus(f.unit().id);
    final check = expectLater(future, throwsA(isA<FactoryFailure>()));
    await Future<void>.delayed(Duration.zero);
    await gateway.signOut();
    held!.complete(
      http.Response(
        jsonEncode(f.status('ready')),
        200,
        headers: {'content-type': 'application/json'},
        request: requests.lastWhere((r) => r.url.path.contains('/rpc/')),
      ),
    );
    await check;
  });
}
