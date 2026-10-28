import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:supabase/supabase.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/supabase_gateway.dart';
import 'package:octatrace_workshop/services/memory_pkce.dart';

void main() {
  test(
    'SDK adapter uses authenticated RPCs and no client-side operator grant',
    () async {
      final requests = <http.Request>[];
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
          final path = r.url.path;
          dynamic body;
          if (path.endsWith('/token')) {
            body = {
              'access_token': 'synthetic-access',
              'refresh_token': 'synthetic-refresh',
              'token_type': 'bearer',
              'expires_in': 3600,
              'user': {
                'id': '10000000-0000-4000-8000-000000000001',
                'aud': 'authenticated',
                'role': 'authenticated',
                'email_confirmed_at': '2026-10-26T00:00:00Z',
                'email': 'operator@example.invalid',
                'created_at': '2026-10-26T00:00:00Z',
                'app_metadata': {},
                'user_metadata': {},
              },
            };
          } else if (path.endsWith('/otp')) {
            body = {};
          } else if (path.endsWith('/workshop_overview')) {
            body = {'articles': [], 'devices': [], 'runs': []};
          } else if (path.endsWith('/workshop_authorize')) {
            body = {'operator_user_id': '10000000-0000-4000-8000-000000000001'};
          } else if (path.endsWith('/logout')) {
            body = {};
          } else {
            body = '20000000-0000-4000-8000-000000000001';
          }
          return http.Response(
            jsonEncode(body),
            200,
            headers: {'content-type': 'application/json'},
            request: r,
          );
        }),
      );
      final gateway = SupabaseGateway.withClient(client, pkce);
      addTearDown(gateway.dispose);
      expect(gateway.accountId, isNull);
      expect(gateway.accountEmail, isNull);
      await expectLater(gateway.load(), throwsA(isA<SessionExpired>()));
      await gateway.requestLink('operator@example.invalid');
      await gateway.exchangeLink('synthetic-code');
      expect(gateway.accountEmail, 'operator@example.invalid');
      await gateway.authorizeOperator();
      expect(gateway.accountId, '10000000-0000-4000-8000-000000000001');
      expect((await gateway.load()).devices, isEmpty);
      await gateway.createArticle(
        code: 'LINK',
        name: 'LINK',
        role: 'Link',
        caseVersion: 'A',
        parts: [],
      );
      await gateway.addRevision(
        articleId: 'article',
        caseVersion: 'B',
        parts: [],
      );
      expect(
        await gateway.reserve(
          requestId: 'request',
          revisionId: 'revision',
          serialClass: 'D',
        ),
        '20000000-0000-4000-8000-000000000001',
      );
      await gateway.recordDiagnostic(
        requestId: 'evidence',
        deviceId: 'device',
        report: {'ok': false},
      );
      final rpc = requests.where((r) => r.url.path.contains('/rpc/')).toList();
      expect(rpc.length, 6);
      final reservationPayload = jsonDecode(
        requests
            .firstWhere((r) => r.url.path.endsWith('/workshop_reserve_device'))
            .body,
      ) as Map;
      expect(
        reservationPayload.keys,
        unorderedEquals(['p_request_id', 'p_revision_id', 'p_serial_class']),
      );
      final otp = requests.firstWhere((r) => r.url.path.endsWith('/otp'));
      final payload = jsonDecode(otp.body) as Map;
      expect(payload['create_user'], false);
      expect(payload['code_challenge_method'], 's256');
      expect(payload['code_challenge'], isNotEmpty);
      expect(otp.url.queryParameters['redirect_to'], workshopCallback);
      final exchange = requests.firstWhere(
        (r) => r.url.path.endsWith('/token'),
      );
      expect(exchange.url.queryParameters['grant_type'], 'pkce');
      expect((jsonDecode(exchange.body) as Map)['code_verifier'], isNotEmpty);
      expect(
        await pkce.getItem(key: 'supabase.auth.token-code-verifier'),
        isNull,
      );

      expect(
        rpc.every(
          (r) => r.headers['Authorization'] == 'Bearer synthetic-access',
        ),
        isTrue,
      );
      expect(rpc.every((r) => !r.body.contains('operator_user_id')), isTrue);
      await gateway.signOut();
      expect(gateway.accountId, isNull);
    },
  );
  for (final code in [
    '42501',
    'PGRST301',
    'PGRST303',
    'XX000',
    'mismatched-operator',
    'unconfirmed',
  ]) {
    test(
      'SDK maps $code without trusting a device/account identifier',
      () async {
        final pkce = MemoryPkce();
        final client = SupabaseClient(
          'https://example.invalid',
          'synthetic-publishable',
          authOptions: AuthClientOptions(
            autoRefreshToken: false,
            pkceAsyncStorage: pkce,
          ),
          httpClient: MockClient((r) async {
            if (r.url.path.endsWith('/otp')) {
              return http.Response('{}', 200, request: r);
            }
            if (r.url.path.endsWith('/token')) {
              return http.Response(
                jsonEncode({
                  'access_token': 'synthetic',
                  'refresh_token': 'synthetic',
                  'token_type': 'bearer',
                  'expires_in': 3600,
                  'user': {
                    'id': '10000000-0000-4000-8000-000000000001',
                    'aud': 'authenticated',
                    'role': 'authenticated',
                    'email': 'operator@example.invalid',
                    'email_confirmed_at': code == 'unconfirmed'
                        ? null
                        : '2026-10-26T00:00:00Z',
                    'created_at': '2026-10-26T00:00:00Z',
                    'app_metadata': {},
                    'user_metadata': {},
                  },
                }),
                200,
                headers: {'content-type': 'application/json'},
                request: r,
              );
            }
            if (code == 'mismatched-operator') {
              return http.Response(
                jsonEncode({'operator_user_id': 'another-account'}),
                200,
                headers: {'content-type': 'application/json'},
                request: r,
              );
            }
            return http.Response(
              jsonEncode({
                'code': code,
                'message': 'synthetic error',
                'details': null,
                'hint': null,
              }),
              403,
              headers: {'content-type': 'application/json'},
              request: r,
            );
          }),
        );
        final gateway = SupabaseGateway.withClient(client, pkce);
        addTearDown(gateway.dispose);
        await gateway.requestLink('operator@example.invalid');
        if (code == 'unconfirmed') {
          await expectLater(
            gateway.exchangeLink('synthetic-code'),
            throwsA(isA<SessionExpired>()),
          );
          return;
        }
        await gateway.exchangeLink('synthetic-code');
        final matcher = code == '42501' || code == 'mismatched-operator'
            ? isA<OperatorDenied>()
            : code.startsWith('PGRST')
            ? isA<SessionExpired>()
            : isA<PostgrestException>();
        await expectLater(gateway.authorizeOperator(), throwsA(matcher));
      },
    );
  }
}
