import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/bench_session.dart';
import '../domain/bench_definition.dart';
import '../domain/registry.dart';

/// Fingerprint the actual installed macOS bundle, including Flutter's debug
/// kernel/assets, native executable and embedded frameworks. Stream file bytes.
Future<String> workshopBundleFingerprint([Directory? bundle]) async {
  final contents = bundle ?? File(Platform.resolvedExecutable).parent.parent;
  if (bundle == null && !contents.path.endsWith('.app/Contents')) {
    throw const FileSystemException('Run from a Workshop app bundle');
  }
  final paths = await contents
      .list(recursive: true, followLinks: false)
      .where((e) => e is File)
      .cast<File>()
      .toList();
  paths.sort((a, b) => a.path.compareTo(b.path));
  if (paths.isEmpty) {
    throw const FileSystemException('Workshop bundle is empty');
  }
  final manifest = StringBuffer();
  for (final file in paths) {
    manifest.write(
      jsonEncode([
        file.path.substring(contents.path.length + 1),
        (await sha256.bind(file.openRead()).first).toString(),
      ]),
    );
    manifest.writeln();
  }
  return benchHash(manifest.toString());
}

/// Each generation is independently readable. A hard link publishes all flushed
/// bytes in one operation and refuses an existing destination across concurrent
/// local processes. Interrupted staging files never replace a committed file.
Future<void> publishBenchFile(File destination, String text) async {
  final temp = await destination.parent.createTemp('.bench-');
  try {
    final staged = File('${temp.path}/payload');
    await staged.writeAsString(text, flush: true);
    final permission = await Process.run('/bin/chmod', ['600', staged.path]);
    if (permission.exitCode != 0 ||
        (await Process.run('/bin/ln', [
              staged.path,
              destination.path,
            ])).exitCode !=
            0) {
      throw const FileSystemException(
        'Cannot publish report at this destination',
      );
    }
  } finally {
    await temp.delete(recursive: true);
  }
}

String benchEnvelope(Json report) {
  final payload = jsonEncode(report);
  return jsonEncode({'sha256': benchHash(payload), 'report': report});
}

Json readBenchEnvelope(String bytes, String account, String id) {
  final envelope = jsonDecode(bytes) as Json;
  final report = envelope['report'] as Json;
  if (report['id'] != id ||
      report['operator'] != account ||
      envelope['sha256'] != benchHash(jsonEncode(report)) ||
      benchHash(report['definition_snapshot']) != report['definition_sha256']) {
    throw const FormatException('Bench report binding or checksum differs');
  }
  final definition = BenchDefinition.fromSnapshot(
    report['definition_snapshot'],
  );
  final firmware = report['firmware'] as Json;
  if (report['definition_key'] != definition.guide['key'] ||
      report['definition_revision'] != definition.guide['revision'] ||
      !definition.builds.any(
        (b) =>
            b.role == report['device']['role'] &&
            b.role == firmware['role'] &&
            b.source == firmware['source'] &&
            b.artifact == firmware['artifact'] &&
            b.version == firmware['version'],
      )) {
    throw const FormatException('Saved procedure or expected firmware differs');
  }
  for (final item in report['artifacts']) {
    final text = item['content'] as String;
    if (utf8.encode(text).length != item['bytes'] ||
        benchHash(text) != item['sha256']) {
      throw const FormatException('Bench artifact checksum differs');
    }
  }
  return report;
}
