import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';

final qrVectors =
    jsonDecode(File('vendor/claim-qr/vectors.json').readAsStringSync()) as Json;
Json qrRow([String role = 'Link']) =>
    List<Json>.from(qrVectors['valid'] as List).firstWhere(
      (r) =>
          (r['fields'] as Json)['environment'] == 'development' &&
          (r['fields'] as Json)['role'] == role,
    );
Json qrFields([String role = 'Link']) => qrRow(role)['fields'] as Json;
const proof = '99000000-0000-4000-8000-000000000001';
const enrollment = '99000000-0000-4000-8000-000000000002';
const request = '99000000-0000-4000-8000-000000000003';
const account = '99000000-0000-4000-8000-000000000004';
const revision = '99000000-0000-4000-8000-000000000005';
DeviceRecord unit({
  String role = 'Link',
  String? owner,
  String state = 'provisioned',
  String prefix = 'D',
}) => DeviceRecord.fromJson({
  'id': qrFields(role)['device_uuid'],
  'serial': '${prefix}000000000001',
  'article_revision_id': revision,
  'provisioning_state': state,
  'owner_user_id': owner,
});
ArticleRevision article([String role = 'Link']) => ArticleRevision.fromJson({
  'id': revision,
  'article_id': enrollment,
  'code': '${role.toUpperCase()}-TEST',
  'name': 'Synthetic fixture',
  'role': role,
  'revision': 1,
  'case_version': 'A',
  'parts': <Json>[],
});
Json status(String state, {String role = 'Link'}) => {
  'v': 1,
  'device_id': unit(role: role).id,
  'state': state,
  if (state != 'not_enrolled') ...{
    'enrollment_id': enrollment,
    'environment': 'development',
    'role': role,
    'public_key_sha256': qrFields(role)['public_key_sha256'],
    'credential_sha256': state == 'ready' ? 'aa' * 32 : null,
  },
};

class FactoryFake implements FactoryGateway {
  String role = 'Link', state = 'not_enrolled';
  Object? failure;
  Completer<Json>? holdStatus, holdIssue;
  Completer<String>? holdReveal;
  int statuses = 0, issues = 0, reveals = 0;
  final requests = <String>[];
  Json? issuedStatus;
  String? payload;
  @override
  Future<Json> factoryStatus(String deviceId) async {
    statuses++;
    if (failure != null) throw failure!;
    return holdStatus != null
        ? await holdStatus!.future
        : status(state, role: role);
  }

  @override
  Future<Json> issueFactory({
    required String requestId,
    required String provisioningRequestId,
    required String deviceId,
    required String role,
  }) async {
    issues++;
    requests.add(requestId);
    if (failure != null) throw failure!;
    if (holdIssue != null) return holdIssue!.future;
    state = 'ready';
    return issuedStatus ??
        {'public_key_sha256': qrFields(role)['public_key_sha256']};
  }

  @override
  Future<String> revealFactory({
    required String requestId,
    required String deviceId,
  }) async {
    reveals++;
    if (failure != null) throw failure!;
    return holdReveal != null
        ? await holdReveal!.future
        : payload ?? qrRow(role)['text'] as String;
  }
}
