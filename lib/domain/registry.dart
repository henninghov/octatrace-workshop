typedef Json = Map<String, dynamic>;

const workshopCallback = 'com.octatrace.workshop://login-callback';

final class ArticleRevision {
  ArticleRevision.fromJson(Json j)
    : id = j['id'] as String,
      articleId = j['article_id'] as String,
      code = j['code'] as String,
      name = j['name'] as String,
      role = j['role'] as String,
      revision = j['revision'] as int,
      caseVersion = j['case_version'] as String,
      parts = List<Json>.from(j['parts'] as List);
  final String id, articleId, code, name, role, caseVersion;
  final int revision;
  final List<Json> parts;
}

final class DeviceRecord {
  DeviceRecord.fromJson(Json j)
    : id = j['id'] as String,
      serial = j['serial'] as String,
      revisionId = j['article_revision_id'] as String,
      state = j['provisioning_state'] as String,
      ownerId = j['owner_user_id'] as String?,
      firmwareVersion = j['firmware_version'] as String?;
  final String id, serial, revisionId, state;
  final String? ownerId, firmwareVersion;
}

final class Registry {
  Registry.fromJson(Json j)
    : articles = List<Json>.from(j['articles'] as List)
          .map(ArticleRevision.fromJson)
          .toList(growable: false),
      devices = List<Json>.from(j['devices'] as List)
          .map(DeviceRecord.fromJson)
          .toList(growable: false),
      runs = List<Json>.from(j['runs'] as List);
  final List<ArticleRevision> articles;
  final List<DeviceRecord> devices;
  final List<Json> runs;
}

abstract interface class WorkshopGateway {
  String? get accountId;
  String? get accountEmail;
  Future<void> requestLink(String email);
  Future<void> exchangeLink(String code);
  Future<void> authorizeOperator();
  Future<void> signOut();
  Future<Registry> load();
  Future<void> createArticle({
    required String code,
    required String name,
    required String role,
    required String caseVersion,
    required List<Json> parts,
  });
  Future<void> addRevision({
    required String articleId,
    required String caseVersion,
    required List<Json> parts,
  });
  Future<void> reserve({
    required String requestId,
    required String revisionId,
    required String serialClass,
  });
  Future<void> recordDiagnostic({
    required String requestId,
    required String deviceId,
    required Json report,
  });
  Future<void> dispose();
}

final class OperatorDenied implements Exception {}

final class SessionExpired implements Exception {}
