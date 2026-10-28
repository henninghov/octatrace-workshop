import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:supabase/supabase.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/supabase_gateway.dart';
import 'package:octatrace_workshop/services/memory_pkce.dart';

import 'provisioning_test.dart' as p;
import 'widget_test.dart' as f;

void main() {
  late SupabaseGateway gateway;
  late List<http.Request> requests;
  late int status;
  late dynamic reply;
  Completer<http.Response>? held;
  setUp(() {
    requests = [];
    status = 200;
    reply = {'version': 1, 'ok': true, 'error': null, 'device_id': f.device};
    held = null;
    final pkce = MemoryPkce();
    final client = SupabaseClient(
      'https://example.invalid',
      'synthetic-publishable',
      authOptions: AuthClientOptions(
        autoRefreshToken: false,
        pkceAsyncStorage: pkce,
      ),
      httpClient: MockClient((r) async {
        requests.add(r);
        dynamic body;
        var code = 200;
        if (r.url.path.endsWith('/token')) {
          body = {
            'access_token': 'synthetic-access',
            'refresh_token': 'synthetic-refresh',
            'token_type': 'bearer',
            'expires_in': 3600,
            'user': {
              'id': f.actor,
              'aud': 'authenticated',
              'role': 'authenticated',
              'email_confirmed_at': '2026-10-28T00:00:00Z',
              'email': f.email,
              'created_at': '2026-10-28T00:00:00Z',
              'app_metadata': {},
              'user_metadata': {},
            },
          };
        } else if (r.url.path.contains('/functions/')) {
          if (held != null) return held!.future;
          body = reply;
          code = status;
        } else if (r.url.path.endsWith('/workshop_begin_provisioning')) {
          body = {
            'request_id': p.requestId,
            'device_id': f.device,
            'state': 'started',
          };
        } else {
          body = {};
        }
        return http.Response(
          jsonEncode(body),
          code,
          headers: {'content-type': 'application/json'},
          request: r,
        );
      }),
    );
    gateway = SupabaseGateway.withClient(client, pkce);
  });
  tearDown(() async {
    await gateway.dispose();
  });
  Future<void> login() async {
    await gateway.requestLink(f.email);
    await gateway.exchangeLink('synthetic');
  }

  Future<void> complete() => gateway.completeProvisioning(
    requestId: p.requestId,
    deviceId: f.device,
    report: p.proof(),
  );

  test('begin uses checked RPC; completion uses user-authenticated server verifier', () async {
    await login();
    final result = await gateway.beginProvisioning(
      requestId: p.requestId,
      deviceId: f.device,
      hardware: p.hardware,
      build: p.build,
    );
    expect(result['state'], 'started');
    final rpc = requests.last;
    expect(jsonDecode(rpc.body), {
      'p_request_id': p.requestId,
      'p_device_id': f.device,
      'p_hardware': p.hardware,
      'p_source': p.build.source,
      'p_artifact': p.build.artifact,
      'p_version': p.build.version,
    });
    expect(rpc.headers['Authorization'], 'Bearer synthetic-access');
    await complete();
    final function = requests.last;
    expect(function.url.path, '/functions/v1/workshop-provisioning');
    expect(function.headers['Authorization'], 'Bearer synthetic-access');
    expect(jsonDecode(function.body), {
      'request_id': p.requestId,
      ...p.proof(),
    });
    expect(
      requests.any(
        (r) => r.url.path.endsWith('/workshop_complete_provisioning'),
      ),
      isFalse,
    );
  });
  test('missing session, expired authorization and revoked operator cannot complete', () async {
    await expectLater(complete(), throwsA(isA<SessionExpired>()));
    await login();
    status = 401;
    await expectLater(complete(), throwsA(isA<SessionExpired>()));
    status = 403;
    await expectLater(complete(), throwsA(isA<OperatorDenied>()));
    status = 404;
    await expectLater(complete(), throwsA(isA<ProvisioningFailure>()));
    status = 422;
    await expectLater(complete(), throwsA(isA<ProvisioningFailure>()));
  });
  test('only an exact successful server confirmation is accepted', () async {
    await login();
    for (final response in [
      null,
      [],
      {'version': 2, 'ok': true, 'device_id': f.device},
      {'version': 1, 'ok': false, 'device_id': f.device},
      {'version': 1, 'ok': true, 'device_id': f.other},
    ]) {
      reply = response;
      await expectLater(complete(), throwsA(isA<ProvisioningFailure>()));
    }
    status = 201;
    reply = {'version': 1, 'ok': true, 'device_id': f.device};
    await expectLater(complete(), throwsA(isA<ProvisioningFailure>()));
  });
  test(
    'logout during verifier call cannot return success to a new session',
    () async {
      await login();
      held = Completer();
      final future = complete();
      final outcome = expectLater(future, throwsA(isA<ProvisioningFailure>()));
      while (!requests.any((r) => r.url.path.contains('/functions/'))) {
        await Future<void>.delayed(Duration.zero);
      }
      await gateway.signOut();
      held!.complete(
        http.Response(
          jsonEncode(reply),
          200,
          headers: {'content-type': 'application/json'},
        ),
      );
      await outcome;
    },
  );
}
