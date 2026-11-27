import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/firmware_checks.dart';
import '../domain/registry.dart';
import 'bench_files.dart';
import 'tool_environment.dart';

/// Runs only the reviewed host-test adapter and keeps its reports per operator.
final class ProcessFirmwareChecks implements FirmwareChecks {
  ProcessFirmwareChecks({
    required this.firmwareRoot,
    required this.evidenceRoot,
    required this.adapter,
    required this.definition,
    required this.newId,
    required this.workshopFingerprint,
    DateTime Function()? now,
    Future<bool> Function(String)? protect,
    this.timeout = const Duration(minutes: 31),
    this.cancelTimeout = const Duration(seconds: 5),
  }) : now = now ?? DateTime.now,
       protect = protect ?? _protect;
  final String firmwareRoot;
  final Directory evidenceRoot;
  final String adapter, definition;
  final String Function() newId;
  final Future<String> Function() workshopFingerprint;
  final DateTime Function() now;
  final Future<bool> Function(String) protect;
  final Duration timeout, cancelTimeout;
  static const adapterDigest =
      '9fe55512f8762069c049957ec0c4297b54519c074c86f9d11af3542dd6c39a5d';
  static const definitionDigest =
      'ed0188af403b5f5232ea19b692c008b8b5c56c1d9726b599367aeb8c8126dfd5';
  static const seventhDefinitionDigest =
      '1a13e143fd5639247726a4197625cc241f316e2eb4c00655b427c223777713b8';
  static const sixthDefinitionDigest =
      'dccff7e6b0ff50cef98efde688ac6d28e79e8680e187b5c70491f49371f54d78';
  static const fifthDefinitionDigest =
      '3a683438374cdde4251e1e6fb7fa588f450b8aa8a9ef6674b06d77dffe615369';
  static const fourthDefinitionDigest =
      '9b7a6672f76c8063ecfd4508eaf14d654ed0368243191a2be1bd833381ff2144';
  static const thirdDefinitionDigest =
      '8c4ee9eec754cb991320c85dc788a31ec35686d226cb8cd85c3085927f2a649e';
  static const secondDefinitionDigest =
      '4f97b9a13af2497c88e09697d14b8cbbbe4ff5a0c9d255910f9252380c3a5ad5';
  static const legacyDefinitionDigest =
      'f0ed16d12fb93f643732c4523b0ecd89d389d2d7c92dcbe9a32fc2a32976e476';
  // Keep reviewed older adapters here when publishing a new revision.
  static const reviewedAdapterDigests = {
    adapterDigest,
    'd9110cc0c61cc8c776e37adb998a2b39cd23cd470bf91d9339bd6f61b40cd489',
    '2310e92161f4fb7655256f679616633954406f59ff6169e22aa401ff64951006',
    'cc94a7adebaa16ccbd2813b317a23106e065cdaea45dc5243e09fb2af98d8713',
    '621f85778e14546927697dbbe5756d8f2058cff880b61e1c5323cf37963fcc02',
    'ba47c5465dfc0eb16f22a632772088c0614b72a6fa83827504db3ebfad1b6790',
    'abaadceec640d0ef8d6f8744a1c9778c1b0ea01c36595731455c4be64c5be263',
    '82e5b24ce8f7d0cf6a158281f72cc992ad539060eb36f9790ac1f90c25fba7de',
    '3357077c8f129caa06a43502423539ad04d17a52c483dc54a241ec3e3e2954b1',
    'c12bf36183ac5dc98bfc1e142d9c3a32f9569cdc84c67df5b89178d90e29339f',
    '4e11035879695b11e1f05a5c79d5faa014ba63f4ee3642e278866066e8fc5010',
  };
  static final _id = RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$');
  Process? _process;
  bool _busy = false;
  bool _cancelled = false;

  static Future<bool> _protect(String path) async =>
      (await Process.run('/bin/chmod', ['700', path])).exitCode == 0;

  Future<Directory> _folder(String account) async {
    if (!_id.hasMatch(account)) {
      throw const FormatException('Operator UUID required');
    }
    final accountDir = Directory('${evidenceRoot.path}/$account');
    final dir = Directory('${accountDir.path}/firmware-host');
    for (final folder in [evidenceRoot, accountDir, dir]) {
      if (await FileSystemEntity.type(folder.path, followLinks: false) ==
          FileSystemEntityType.link) {
        throw const FormatException(
          'Host evidence folder cannot be a symbolic link',
        );
      }
      await folder.create(recursive: true);
      if (!await protect(folder.path)) {
        throw const FileSystemException('Cannot protect host test evidence');
      }
    }
    return dir;
  }

  Future<File> _support(
    Directory dir,
    String name,
    String text,
    String digest,
  ) async {
    if (sha256.convert(utf8.encode(text)).toString() != digest) {
      throw const FormatException('Reviewed host test support differs');
    }
    final file = File('${dir.path}/$name');
    final type = await FileSystemEntity.type(file.path, followLinks: false);
    if (type == FileSystemEntityType.notFound) {
      await publishBenchFile(file, text);
    } else if (type != FileSystemEntityType.file ||
        sha256.convert(await file.readAsBytes()).toString() != digest) {
      throw const FormatException('Saved host test support differs');
    }
    return file;
  }

  Future<Json> _call(
    String python,
    File script,
    List<String> arguments, {
    bool acceptFailure = false,
  }) async {
    if (python.isEmpty || !python.startsWith('/')) {
      throw const FormatException('Choose an absolute Python executable path');
    }
    final process = await Process.start(
      python,
      ['-B', script.path, ...arguments],
      runInShell: false,
      environment: workshopToolEnvironment(),
    );
    _process = process;
    if (_cancelled) process.kill();
    try {
      Future<List<int>> capture(Stream<List<int>> stream) async {
        final bytes = <int>[];
        await for (final part in stream) {
          if (bytes.length + part.length > 1024 * 1024) {
            process.kill();
            throw const FormatException(
              'Host test adapter output limit exceeded',
            );
          }
          bytes.addAll(part);
        }
        return bytes;
      }

      final output =
          await Future.wait<Object>([
            capture(process.stdout),
            capture(process.stderr),
            process.exitCode,
          ]).timeout(
            timeout,
            onTimeout: () async {
              await _stop(process);
              throw TimeoutException('Host test adapter deadline exceeded');
            },
          );
      if (output[2] != 0 && !acceptFailure) {
        throw StateError(
          'Host test operation failed: ${utf8.decode(output[1] as List<int>)}',
        );
      }
      final parsed = jsonDecode(utf8.decode(output[0] as List<int>));
      if (parsed is! Json) {
        throw const FormatException('Invalid host test report');
      }
      if ((parsed['status'] == 'passed') != (output[2] == 0) && acceptFailure) {
        throw const FormatException('Host test result and exit status differ');
      }
      return parsed;
    } finally {
      _process = null;
    }
  }

  Future<T> _exclusive<T>(Future<T> Function() work) async {
    if (_busy) throw StateError('A host test operation is already running');
    _busy = true;
    _cancelled = false;
    try {
      return await work();
    } finally {
      _busy = false;
    }
  }

  Future<void> _verifyPassed(
    Directory folder,
    Json result,
    String account,
  ) async {
    if (result['status'] != 'passed') return;
    if (await FileSystemEntity.type(folder.path, followLinks: false) !=
        FileSystemEntityType.directory) {
      throw const FormatException('Saved host attempt folder is missing');
    }
    final source = result['firmware_source_id'];
    final selectedDefinition = result['definition_sha256'];
    if (source is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(source) ||
        !{
          definitionDigest,
          seventhDefinitionDigest,
          sixthDefinitionDigest,
          fifthDefinitionDigest,
          fourthDefinitionDigest,
          thirdDefinitionDigest,
          secondDefinitionDigest,
          legacyDefinitionDigest,
        }.contains(selectedDefinition) ||
        !reviewedAdapterDigests.contains(result['adapter_sha256']) ||
        result['exit_code'] != 0 ||
        !FirmwareHostSuite.values
            .map((suite) => suite.name)
            .contains(result['suite'])) {
      throw const FormatException('Passed host result is missing its bindings');
    }
    Future<String> read(String name, Object? expected) async {
      final file = File('${folder.path}/$name');
      if (expected is! String ||
          await FileSystemEntity.type(file.path, followLinks: false) !=
              FileSystemEntityType.file) {
        throw const FormatException('Saved host evidence is missing');
      }
      final bytes = await file.readAsBytes();
      if (sha256.convert(bytes).toString() != expected) {
        throw const FormatException('Saved host evidence differs');
      }
      return utf8.decode(bytes);
    }

    for (final name in ['started.json', 'completed.json']) {
      if (await FileSystemEntity.type(
            '${folder.path}/$name',
            followLinks: false,
          ) !=
          FileSystemEntityType.file) {
        throw const FormatException('Saved host attempt record is missing');
      }
    }
    final started = jsonDecode(
      await File('${folder.path}/started.json').readAsString(),
    ) as Json;
    final completed = jsonDecode(
      await File('${folder.path}/completed.json').readAsString(),
    ) as Json;
    if (started['id'] != result['id'] ||
        started['operator'] != account ||
        result['operator'] != account ||
        started['workshop_fingerprint'] != result['workshop_fingerprint'] ||
        result['workshop_fingerprint'] is! String ||
        !RegExp(r'^[0-9a-f]{64}$')
            .hasMatch(result['workshop_fingerprint'] as String) ||
        started['suite'] != result['suite'] ||
        started['definition_sha256'] != selectedDefinition ||
        jsonEncode(completed) != jsonEncode(result)) {
      throw const FormatException('Saved host attempt binding differs');
    }
    final savedDefinition =
        jsonDecode(await read('definition.json', selectedDefinition)) as Json;
    await read('adapter.py', result['adapter_sha256']);
    final log = await read('output.log', result['log_sha256']);
    final catalog = jsonDecode(
      await read('catalog.json', result['catalog_sha256']),
    ) as Json;
    final report = jsonDecode(
      await read('runner-report.json', result['runner_report_sha256']),
    ) as Json;
    final cases = catalog['python_case_ids'];
    final baseline = savedDefinition['baseline_python_case_ids'] as List;
    final suite = result['suite'];
    if (selectedDefinition != legacyDefinitionDigest) {
      final inputs =
          jsonDecode(await read('source-inputs.json', source)) as Json;
      if (suite == 'sessionControl') {
        final evidence = jsonDecode(
          await read(
            'qualification-evidence.json',
            result['qualification_evidence_sha256'],
          ),
        ) as Json;
        final lines = log
            .split('\n')
            .where((line) => line.startsWith('PASS session '))
            .toList();
        const names = [
          'wire',
          'journal',
          'participant',
          'coordinator',
          'attempt',
          'flash',
          'core_radio',
          'link_radio',
          'bluetooth',
          'phone_channel',
          'phone_handler',
        ];
        final negative = evidence.entries
            .where(
              (entry) =>
                  RegExp(r'^negative-[0-8]-[^/]+/result\.log$')
                      .hasMatch(entry.key),
            )
            .toList();
        final coverage = report['coverage'];
        if (!{
              definitionDigest,
              seventhDefinitionDigest,
              sixthDefinitionDigest,
              fifthDefinitionDigest,
              fourthDefinitionDigest,
              thirdDefinitionDigest,
            }.contains(selectedDefinition) ||
            report['source_id'] != source ||
            report['negative_controls'] != 9 ||
            report['runtime_integration'] != 'not run' ||
            report['physical'] != 'not run' ||
            report['qualification_evidence_sha256'] !=
                result['qualification_evidence_sha256'] ||
            lines.length != 11 ||
            lines.toSet().length != 11 ||
            evidence.length != 21 ||
            names.any(
              (name) =>
                  evidence['$name.log'] is! String ||
                  !(evidence['$name.log'] as String).startsWith(
                    'PASS session ',
                  ),
            ) ||
            negative.length != 9 ||
            negative.any(
              (entry) =>
                  entry.value is! String ||
                  !(entry.value as String).contains('runtime_error'),
            ) ||
            coverage is! Map ||
            coverage.length != 15 ||
            evidence['coverage-summary.json'] is! String ||
            jsonEncode(
                  jsonDecode(evidence['coverage-summary.json'] as String),
                ) !=
                jsonEncode(coverage) ||
            coverage.values.any(
              (row) =>
                  row is! Map ||
                  row['lines'] is! Map ||
                  row['lines']['percent'] != 100 ||
                  row['branches'] is! Map ||
                  (row['branches']['count'] > 0 &&
                      row['branches']['percent'] < 95),
            )) {
          throw const FormatException(
            'Session qualification evidence is incomplete',
          );
        }
      } else if (suite != 'host' && suite != 'tooling') {
        final files = (suite == 'setupTransfer'
            ? report['source_files_sha256']
            : report['source_files']);
        if (files is! Map ||
            files.isEmpty ||
            files.entries.any((entry) => inputs[entry.key] != entry.value)) {
          throw const FormatException(
            'Qualification inputs differ from the firmware source',
          );
        }
        if (suite == 'authorityLayout') {
          const baseline =
              'b63c26182f169452c16808136abb96f534cb5d597fddbe356c04703f49bd6ec4';
          const measured = {
            'tools/build_firmware.py',
            'tools/provision_platform.py',
            'tools/provision_preparation.py',
            'tools/control_storage_manifest.py',
          };
          final testsLog = await read(
            'layout-tests.log',
            result['layout_tests_log_sha256'],
          );
          final buildLog = await read(
            'layout-build.log',
            result['layout_build_log_sha256'],
          );
          final coverage = jsonDecode(
            await read(
              'layout-coverage.json',
              result['layout_coverage_json_sha256'],
            ),
          ) as Json;
          final encodedFile = File('${folder.path}/layout-coverage.b64');
          if (await FileSystemEntity.type(
                encodedFile.path,
                followLinks: false,
              ) !=
              FileSystemEntityType.file) {
            throw const FormatException('Layout coverage evidence is missing');
          }
          final coverageBytes = base64Decode(await encodedFile.readAsString());
          final testCounts = RegExp(r'Ran (\d+) tests')
              .allMatches(testsLog)
              .toList();
          final built = jsonDecode(buildLog.trim().split('\n').last) as Json;
          final changed = report['changed_existing_tooling_coverage'];
          final roles = report['roles'];
          final resource = report['resource_probe'];
          if (!{
                definitionDigest,
                seventhDefinitionDigest,
                sixthDefinitionDigest,
              }.contains(selectedDefinition) ||
              report['source_id'] != source ||
              inputs['tests/baselines/c433-authority-layout.v1.json'] !=
                  baseline ||
              report['baseline_sha256'] != baseline ||
              sha256.convert(coverageBytes).toString() !=
                  result['layout_coverage_sha256'] ||
              report['build_coverage_sha256'] !=
                  result['layout_coverage_sha256'] ||
              testCounts.isEmpty ||
              int.parse(testCounts.last.group(1)!) != cases.length ||
              testsLog.contains('skipped=') ||
              built['source_id'] != source ||
              coverage['files'] is! Map ||
              !measured.every((name) => coverage['files'].containsKey(name)) ||
              report['unit_tests'] is! int ||
              report['unit_tests'] < 12 ||
              changed is! Map ||
              !measured.every(
                (name) =>
                    changed[name] is Map &&
                    changed[name]['changed_executable_lines'] is List &&
                    changed[name]['covered'] ==
                        changed[name]['changed_executable_lines'].length,
              ) ||
              roles is! Map ||
              !{'Link', 'Core'}.every(
                (role) => roles[role] is Map && roles[role]['flashed'] == false,
              ) ||
              resource is! Map ||
              resource['result'] != 'pass' ||
              resource['source_id'] != source) {
            throw const FormatException(
              'Authority layout evidence is incomplete',
            );
          }
        } else if (suite == 'authorityResources' || suite == 'fieldResources') {
          final negative = report['negative_controls'];
          final coverage = report['coverage'];
          if (!{
                definitionDigest,
                seventhDefinitionDigest,
                sixthDefinitionDigest,
                fifthDefinitionDigest,
              }.contains(selectedDefinition) ||
              report['source_id'] != source ||
              negative is! List ||
              negative.length != 2 ||
              coverage is! Map ||
              (suite == 'authorityResources' &&
                  (report['arm_workspace_bytes'] is! int ||
                      report['arm_workspace_bytes'] > 12288 ||
                      report['measured_header'] is! Map ||
                      report['measured_header']['lines']['percent'] != 100 ||
                      report['measured_header']['branches']['percent'] !=
                          100)) ||
              (suite == 'fieldResources' &&
                  (coverage.length != 9 ||
                      report['allocation_failure_boundaries'] != 65 ||
                      report['linked'] is! Map ||
                      !{
                        'link',
                        'core',
                      }.every((role) => report['linked'].containsKey(role)) ||
                      coverage.values.any(
                        (row) =>
                            row is! Map ||
                            row['lines']['percent'] != 100 ||
                            row['branches']['percent'] < 95,
                      )))) {
            throw const FormatException(
              'Resource qualification evidence is incomplete',
            );
          }
          if (suite == 'fieldResources') {
            await read(
              'prerequisite-host.log',
              result['prerequisite_log_sha256'],
            );
            final prerequisite = jsonDecode(
              await read(
                'prerequisite-host-report.json',
                result['prerequisite_report_sha256'],
              ),
            ) as Json;
            if (prerequisite['result'] != 'pass' ||
                prerequisite['source_id'] != source ||
                prerequisite['cpp_cases_per_role'] != 128) {
              throw const FormatException(
                'Field resource prerequisite differs',
              );
            }
          }
        } else if (suite != 'setupTransfer' && suite != 'fieldHandshake') {
          final keys = files.keys.cast<String>().toList()..sort();
          final serialized =
              '{${keys.map((key) => '${jsonEncode(key)}: ${jsonEncode(files[key])}').join(', ')}}';
          if (sha256.convert(utf8.encode(serialized)).toString() !=
              report['contract_input_id']) {
            throw const FormatException(
              'Qualification contract identity differs',
            );
          }
        }
        const minimumTests = {
          'authorityStorage': 16,
          'claimQr': 20,
          'deviceAuthority': 18,
          'deviceCredential': 14,
          'fieldHandshake': 12,
          'proofContext': 16,
          'setupTransfer': 12,
        };
        if (suite != 'authorityResources' &&
            suite != 'fieldResources' &&
            suite != 'authorityLayout') {
          final count =
              report[suite == 'fieldHandshake' || suite == 'setupTransfer'
                  ? 'tests'
                  : 'unit_tests'];
          if (count is! int || count < (minimumTests[suite] ?? 0)) {
            throw const FormatException(
              'Qualification test evidence is incomplete',
            );
          }
        }
      }
    } else if (suite != 'host' && suite != 'tooling') {
      throw const FormatException(
        'Legacy definition does not cover this suite',
      );
    }
    if (catalog['source_id'] != source ||
        cases is! List ||
        cases.toSet().length != cases.length ||
        !cases.toSet().containsAll(baseline) ||
        result['discovered_python_cases'] != cases.length ||
        ((suite == 'tooling' ||
                suite == 'host' ||
                suite == 'fieldHandshake' ||
                suite == 'sessionControl' ||
                suite == 'authorityResources' ||
                suite == 'fieldResources' ||
                suite == 'authorityLayout') &&
            report['source_id'] != source) ||
        report['result'] != 'pass' ||
        (result['suite'] == 'tooling' && report['tests'] != cases.length) ||
        (result['suite'] == 'host' && report['cpp_cases_per_role'] != 128)) {
      throw const FormatException(
        'Saved host result does not prove the expected tests',
      );
    }
  }

  @override
  Future<Json> run({
    required String account,
    required FirmwareHostSuite suite,
    required String firmwareRoot,
    required String python,
    required String fonts,
  }) => _exclusive(() async {
    if (!firmwareRoot.startsWith('/') ||
        !await Directory(firmwareRoot).exists()) {
      throw const FormatException(
        'Choose an existing absolute firmware checkout path',
      );
    }
    final dir = await _folder(account);
    final fingerprint = await workshopFingerprint();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(fingerprint)) {
      throw const FormatException('Workshop bundle fingerprint required');
    }
    final script = await _support(
      dir,
      'adapter-$adapterDigest.py',
      adapter,
      adapterDigest,
    );
    final guide = await _support(
      dir,
      'definition-$definitionDigest.json',
      definition,
      definitionDigest,
    );
    final attempt = newId();
    if (!_id.hasMatch(attempt)) {
      throw const FormatException('Attempt UUID required');
    }
    await publishBenchFile(
      File('${dir.path}/request-$attempt.json'),
      jsonEncode({
        'attempt': attempt,
        'operator': account,
        'workshop_fingerprint': fingerprint,
        'suite': suite.name,
        'requested_at': now().toUtc().toIso8601String(),
      }),
    );
    final result = await _call(python, script, [
      '--root',
      firmwareRoot,
      '--python',
      python,
      '--definition',
      guide.path,
      '--definition-sha256',
      definitionDigest,
      '--attempt',
      '${dir.path}/$attempt',
      '--suite',
      suite.name,
      '--operator',
      account,
      '--workshop-fingerprint',
      fingerprint,
      if (fonts.isNotEmpty) ...['--fonts', fonts],
    ], acceptFailure: true);
    if (result['suite'] != suite.name ||
        result['operator'] != account ||
        result['workshop_fingerprint'] != fingerprint ||
        result['id'] != attempt ||
        !{'passed', 'failed', 'cancelled'}.contains(result['status'])) {
      throw const FormatException('Host result belongs to a different request');
    }
    await _verifyPassed(Directory('${dir.path}/$attempt'), result, account);
    return {...result, 'attempt': attempt};
  });

  @override
  Future<List<Json>> history({
    required String account,
    required String python,
  }) => _exclusive(() async {
    final dir = await _folder(account);
    final script = await _support(
      dir,
      'adapter-$adapterDigest.py',
      adapter,
      adapterDigest,
    );
    final folders = await dir
        .list(followLinks: false)
        .where((e) => e is Directory)
        .cast<Directory>()
        .toList();
    folders.sort((a, b) => b.path.compareTo(a.path));
    final reports = <Json>[];
    final seen = <String>{};
    for (final folder in folders) {
      final name = folder.path.split(Platform.pathSeparator).last;
      if (!_id.hasMatch(name)) continue;
      seen.add(name);
      try {
        final report = await _call(python, script, [
          '--operation',
          'inspect',
          '--attempt',
          folder.path,
          '--operator',
          account,
        ]);
        if (report['operator'] != account) {
          throw const FormatException(
            'Host report belongs to another operator',
          );
        }
        if (report['id'] != name) {
          throw const FormatException('Host report attempt identity differs');
        }
        await _verifyPassed(folder, report, account);
        reports.add({...report, 'attempt': name});
      } catch (error) {
        reports.add({
          'attempt': name,
          'status': 'unreadable',
          'reason': error.toString(),
        });
      }
    }
    await for (final entity in dir.list(followLinks: false)) {
      if (entity is! File) continue;
      final name = entity.path.split(Platform.pathSeparator).last;
      if (!name.startsWith('request-') || !name.endsWith('.json')) continue;
      final attempt = name.substring(8, name.length - 5);
      if (!_id.hasMatch(attempt) || seen.contains(attempt)) continue;
      try {
        final request = jsonDecode(await entity.readAsString()) as Json;
        if (request['attempt'] != attempt || request['operator'] != account) {
          throw const FormatException('Request identity differs');
        }
        reports.add({
          ...request,
          'status': 'incomplete',
          'reason': 'No final result is saved; the run may still be active or was interrupted.',
        });
      } catch (error) {
        reports.add({
          'attempt': attempt,
          'status': 'unreadable',
          'reason': error.toString(),
        });
      }
    }
    return reports;
  });

  @override
  Future<String> export({
    required String account,
    required String python,
    required String attempt,
    required String directory,
  }) => _exclusive(() async {
    if (!_id.hasMatch(attempt) || !await Directory(directory).exists()) {
      throw const FormatException(
        'Choose a saved attempt and existing export folder',
      );
    }
    final dir = await _folder(account);
    final destination = File('$directory/firmware-host-$attempt.json');
    final attemptDir = Directory('${dir.path}/$attempt');
    final attemptType = await FileSystemEntity.type(
      attemptDir.path,
      followLinks: false,
    );
    if (attemptType != FileSystemEntityType.notFound &&
        attemptType != FileSystemEntityType.directory) {
      throw const FormatException('Saved host attempt folder differs');
    }
    final startedType = attemptType == FileSystemEntityType.directory
        ? await FileSystemEntity.type(
            '${attemptDir.path}/started.json',
            followLinks: false,
          )
        : FileSystemEntityType.notFound;
    if (startedType == FileSystemEntityType.notFound) {
      final request = File('${dir.path}/request-$attempt.json');
      if (await FileSystemEntity.type(request.path, followLinks: false) !=
          FileSystemEntityType.file) {
        throw const FormatException('Saved host request is missing');
      }
      final snapshot = await request.readAsString();
      final record = jsonDecode(snapshot) as Json;
      if (record['attempt'] != attempt || record['operator'] != account) {
        throw const FormatException('Saved host request binding differs');
      }
      await publishBenchFile(
        destination,
        jsonEncode({
          'format': 1,
          'report': {
            ...record,
            'id': attempt,
            'status': 'incomplete',
            'reason': 'No final result is saved; the run may still be active or was interrupted.',
          },
          'evidence': {'request.json': snapshot},
        }),
      );
      return destination.path;
    }
    if (startedType != FileSystemEntityType.file) {
      throw const FormatException('Saved host attempt record differs');
    }
    final script = await _support(
      dir,
      'adapter-$adapterDigest.py',
      adapter,
      adapterDigest,
    );
    final result = await _call(python, script, [
      '--operation',
      'export',
      '--attempt',
      '${dir.path}/$attempt',
      '--destination',
      destination.path,
      '--operator',
      account,
    ]);
    return result['path'] as String;
  });

  @override
  Future<void> cancel() async {
    _cancelled = true;
    final process = _process;
    if (process == null) return;
    await _stop(process);
  }

  Future<void> _stop(Process process) async {
    process.kill();
    await process.exitCode.timeout(
      cancelTimeout,
      onTimeout: () {
        process.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
  }
}
