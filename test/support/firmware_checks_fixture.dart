import 'dart:async';

import 'package:octatrace_workshop/domain/firmware_checks.dart';
import 'package:octatrace_workshop/domain/registry.dart';

class FakeFirmwareChecks implements FirmwareChecks {
  Completer<Json>? pending;
  FirmwareHostSuite? selectedSuite;
  String? account, selectedAttempt, exportFolder;
  var cancels = 0;
  bool fail = false;
  final reports = <Json>[
    {
      'attempt': 'attempt-a',
      'suite': 'tooling',
      'status': 'passed',
      'operator': 'operator-a',
      'firmware_source_id': 'source-a',
      'workshop_fingerprint': 'workshop-a',
    },
    {
      'attempt': 'attempt-b',
      'suite': 'host',
      'status': 'failed',
      'reason': 'synthetic failure',
    },
  ];

  @override
  Future<Json> run({
    required String account,
    required FirmwareHostSuite suite,
    required String firmwareRoot,
    required String python,
    required String fonts,
  }) {
    this.account = account;
    selectedSuite = suite;
    if (fail) return Future.error(StateError('synthetic run error'));
    pending = Completer<Json>();
    return pending!.future;
  }

  @override
  Future<List<Json>> history({
    required String account,
    required String python,
  }) async {
    if (fail) throw StateError('synthetic history error');
    return reports;
  }

  @override
  Future<String> export({
    required String account,
    required String python,
    required String attempt,
    required String directory,
  }) async {
    if (fail) throw StateError('synthetic export error');
    selectedAttempt = attempt;
    exportFolder = directory;
    return '$directory/report.json';
  }

  @override
  Future<void> cancel() async {
    cancels++;
  }
}
