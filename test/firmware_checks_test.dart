import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/firmware_checks.dart';
import 'package:octatrace_workshop/services/firmware_checks.dart';

const account = '11111111-1111-4111-8111-111111111111';

const fakePython = r'''#!/usr/bin/env python3
import base64,hashlib,json,os,signal,sys,time
args=sys.argv[1:]
def value(name,default=''):
 return args[args.index(name)+1] if name in args else default
mode=value('--operation','run'); attempt=value('--attempt'); root=os.path.basename(value('--root')); operator=value('--operator'); fingerprint=value('--workshop-fingerprint')
if mode=='inspect':
 try: print(open(os.path.join(attempt,'completed.json')).read());sys.exit(0)
 except Exception: print('bad evidence',file=sys.stderr);sys.exit(1)
if mode=='export':
 dest=value('--destination');open(dest,'x').write('{}');print(json.dumps({'path':dest}));sys.exit(0)
os.mkdir(attempt)
if root=='bad-output': print('not json');sys.exit(1)
if root=='nonobject': print('[]');sys.exit(0)
if root=='inconsistent': print(json.dumps({'status':'passed'}));sys.exit(1)
if root=='large': print('x'*1100000);sys.exit(0)
if root=='missing-evidence': print(json.dumps({'status':'passed'}));sys.exit(0)
if root=='ignore':
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 open(os.path.join(attempt,'ready'),'w').write('yes');time.sleep(60)
if root=='sleep':
 signal.signal(signal.SIGTERM,lambda a,b:(print(json.dumps({'id':os.path.basename(attempt),'status':'cancelled','suite':'tooling','operator':operator,'workshop_fingerprint':fingerprint}),flush=True),sys.exit(1)))
 open(os.path.join(attempt,'ready'),'w').write('yes');time.sleep(60)
status='failed' if root=='failure' else 'passed'
suite=value('--suite');inputs={'marker':'b'*64}
if suite=='authorityLayout': inputs['tests/baselines/c433-authority-layout.v1.json']='b63c26182f169452c16808136abb96f534cb5d597fddbe356c04703f49bd6ec4'
source_bytes=json.dumps(inputs,sort_keys=True).encode();source=hashlib.sha256(source_bytes).hexdigest()
def put(name,data):
 path=os.path.join(attempt,name);open(path,'wb').write(data);return hashlib.sha256(data).hexdigest()
definition=open('assets/bench/firmware-host-regression.v1.json' if root=='legacy' else value('--definition'),'rb').read(); adapter=open(args[1],'rb').read()
definition_hash=put('definition.json',definition);adapter_hash=put('adapter.py',adapter)
put('source-inputs.json',source_bytes)
cases=json.loads(definition)['baseline_python_case_ids']
if root=='bad-baseline': cases=[]
catalog=json.dumps({'source_id':source,'python_case_ids':cases}).encode()
files={'marker':'changed'} if root=='bad-qualification-inputs' else inputs
identity='wrong' if root=='bad-contract-identity' else hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
count=0 if root=='bad-qualification-count' else 20
record={'source_id':source,'source_files':files,'source_files_sha256':files,'contract_input_id':identity,'result':'fail' if root=='bad-report' else 'pass','tests':len(cases),'unit_tests':count,'cpp_cases_per_role':128}
if suite in ['authorityResources','fieldResources']:
 record.update({'negative_controls':['one','two'],'coverage':{str(i):{'lines':{'percent':100},'branches':{'percent':100}} for i in range(9)},'arm_workspace_bytes':13000 if root=='bad-resource' else 9040,'measured_header':{'lines':{'percent':100},'branches':{'percent':100}},'allocation_failure_boundaries':65,'linked':{'link':{},'core':{}}})
extra=None;prior_log=None;prior_report=None;layout_fields={};log=b'synthetic'
if suite=='authorityLayout':
 names=['tools/build_firmware.py','tools/provision_platform.py','tools/provision_preparation.py','tools/control_storage_manifest.py']
 binary=b'synthetic coverage';put('layout-coverage.b64',base64.b64encode(binary));coverage_hash=hashlib.sha256(binary).hexdigest()
 layout_fields={'layout_coverage_sha256':coverage_hash,'layout_tests_log_sha256':put('layout-tests.log',('Ran '+str(len(cases))+' tests').encode()),'layout_build_log_sha256':put('layout-build.log',json.dumps({'source_id':source}).encode()),'layout_coverage_json_sha256':put('layout-coverage.json',json.dumps({'files':{name:{} for name in names}}).encode())}
 changed={name:{'changed_executable_lines':[1],'covered':0 if root=='bad-layout' else 1} for name in names}
 record.update({'unit_tests':12,'baseline_sha256':inputs['tests/baselines/c433-authority-layout.v1.json'],'build_coverage_sha256':coverage_hash,'changed_existing_tooling_coverage':changed,'roles':{'Link':{'flashed':False},'Core':{'flashed':False}},'resource_probe':{'result':'pass','source_id':source}})
if suite=='fieldResources':
 prior_log=put('prerequisite-host.log',b'host prerequisite')
 prior_report=put('prerequisite-host-report.json',json.dumps({'result':'pass','source_id':source,'cpp_cases_per_role':128}).encode())
if suite=='sessionControl':
 names=['wire','journal','participant','coordinator','attempt','flash','core_radio','link_radio','bluetooth','phone_channel','phone_handler']
 coverage={str(i):{'lines':{'percent':100},'branches':{'count':2,'percent':100}} for i in range(15)}
 artifacts={name+'.log':'PASS session '+name for name in names}
 artifacts.update({'negative-'+str(i)+'-case/result.log':'runtime_error' for i in range(9)})
 artifacts['coverage-summary.json']=json.dumps(coverage)
 extra=put('qualification-evidence.json',json.dumps(artifacts).encode())
 log='\n'.join('PASS session '+name for name in names).encode()
 record.update({'coverage':coverage,'negative_controls':8 if root=='bad-session' else 9,'physical':'not run','runtime_integration':'not run','qualification_evidence_sha256':extra})
report=json.dumps(record).encode()
catalog_hash=put('catalog.json',catalog);report_hash=put('runner-report.json',report);log_hash=put('output.log',log)
started={'id':os.path.basename(attempt),'operator':operator,'workshop_fingerprint':fingerprint,'suite':suite,'definition_sha256':definition_hash,'status':'running'}
open(os.path.join(attempt,'started.json'),'w').write(json.dumps(started))
result={'id':os.path.basename(attempt),'operator':operator,'workshop_fingerprint':fingerprint,'status':status,'suite':suite,'firmware_source_id':source,'args':args,
 'definition_sha256':definition_hash,'adapter_sha256':adapter_hash,'exit_code':0 if status=='passed' else 1,
 'log_sha256':log_hash,'catalog_sha256':catalog_hash,'runner_report_sha256':report_hash,'discovered_python_cases':len(cases)}
if extra is not None: result['qualification_evidence_sha256']=extra
if prior_log is not None: result.update({'prerequisite_log_sha256':prior_log,'prerequisite_report_sha256':prior_report})
result.update(layout_fields)
if root=='bad-bindings': result['firmware_source_id']='invalid'
if root=='bad-attempt': result['id']='different'
if root=='bad-operator': result['operator']='22222222-2222-4222-8222-222222222222'
if root=='bad-suite': result['suite']='host' if suite=='tooling' else 'tooling'
if root=='bad-workshop': result['workshop_fingerprint']='d'*64
if root=='bad-start': started['workshop_fingerprint']='d'*64;open(os.path.join(attempt,'started.json'),'w').write(json.dumps(started))
if root=='missing-artifact': os.remove(os.path.join(attempt,'catalog.json'))
if root=='bad-hash': open(os.path.join(attempt,'output.log'),'wb').write(b'changed')
open(os.path.join(attempt,'completed.json'),'w').write(json.dumps(result))
print(json.dumps(result));sys.exit(1 if status=='failed' else 0)
''';

void main() {
  late Directory temp;
  late String adapter, definition, python;
  var counter = 0;
  String nextId() =>
      '00000000-0000-4000-8000-${(++counter).toString().padLeft(12, '0')}';
  ProcessFirmwareChecks runner({
    String root = 'fixture',
    String? script,
    String? guide,
    Future<bool> Function(String)? protect,
    Duration? timeout,
    String? fingerprint,
  }) {
    final firmware = Directory('${temp.path}/$root')
      ..createSync(recursive: true);
    return ProcessFirmwareChecks(
      firmwareRoot: firmware.path,
      evidenceRoot: Directory('${temp.path}/evidence'),
      adapter: script ?? adapter,
      definition: guide ?? definition,
      newId: nextId,
      workshopFingerprint: () async => fingerprint ?? 'c' * 64,
      now: () => DateTime.utc(2026, 11, 24),
      protect: protect,
      timeout: timeout ?? const Duration(minutes: 1),
    );
  }

  Future<Map<String, dynamic>> run(
    ProcessFirmwareChecks checks, {
    String user = account,
    String? executable,
    String? firmware,
    FirmwareHostSuite suite = FirmwareHostSuite.tooling,
  }) => checks.run(
    account: user,
    suite: suite,
    firmwareRoot: firmware ?? checks.firmwareRoot,
    python: executable ?? python,
    fonts: '${temp.path}/fonts',
  );

  setUp(() async {
    await Directory('build').create(recursive: true);
    temp = await Directory('build').createTemp('firmware-checks-');
    temp = temp.absolute;
    adapter = await File('tools/firmware_test_adapter.py').readAsString();
    definition = await File('assets/bench/firmware-host-regression.v8.json')
        .readAsString();
    python = '${temp.path}/python';
    await File(python).writeAsString(fakePython);
    expect((await Process.run('/bin/chmod', ['700', python])).exitCode, 0);
    counter = 0;
  });
  tearDown(() async {
    await temp.delete(recursive: true);
  });

  test('run, reopen and export remain operator-scoped', () async {
    final checks = runner();
    final result = await run(checks, suite: FirmwareHostSuite.host);
    expect(result['status'], 'passed');
    expect(result['suite'], 'host');
    expect(result['args'], containsAll(['--fonts', '${temp.path}/fonts']));
    final history = await checks.history(account: account, python: python);
    expect(history.single['attempt'], result['attempt']);
    final folder = await Directory('${temp.path}/exports').create();
    final path = await checks.export(
      account: account,
      python: python,
      attempt: result['attempt'],
      directory: folder.path,
    );
    expect(await File(path).exists(), isTrue);
    expect(
      await checks.history(
        account: '22222222-2222-4222-8222-222222222222',
        python: python,
      ),
      isEmpty,
    );
    await checks.cancel();
  });

  test('tooling receives the selected font directory', () async {
    final result = await run(runner());
    expect(result['status'], 'passed');
    expect(result['args'], containsAll(['--fonts', '${temp.path}/fonts']));
  });

  test('version 1 host evidence remains readable', () async {
    final checks = runner(root: 'legacy');
    final result = await run(checks);
    expect(result['status'], 'passed');
    expect(
      (await checks.history(account: account, python: python)).single['status'],
      'passed',
    );
  });

  test('qualification reports must match the saved firmware inputs', () async {
    final good = await run(runner(), suite: FirmwareHostSuite.claimQr);
    expect(good['status'], 'passed');
    await expectLater(
      run(
        runner(root: 'bad-qualification-inputs'),
        suite: FirmwareHostSuite.claimQr,
      ),
      throwsFormatException,
    );
    for (final root in ['bad-contract-identity', 'bad-qualification-count']) {
      await expectLater(
        run(runner(root: root), suite: FirmwareHostSuite.claimQr),
        throwsFormatException,
      );
    }
    for (final suite in [
      FirmwareHostSuite.fieldHandshake,
      FirmwareHostSuite.setupTransfer,
    ]) {
      expect((await run(runner(), suite: suite))['status'], 'passed');
    }
  });

  test(
    'session qualification requires the recorded cases and negative controls',
    () async {
      expect(
        (await run(
          runner(),
          suite: FirmwareHostSuite.sessionControl,
        ))['status'],
        'passed',
      );
      await expectLater(
        run(
          runner(root: 'bad-session'),
          suite: FirmwareHostSuite.sessionControl,
        ),
        throwsFormatException,
      );
    },
  );

  test(
    'resource qualification requires complete source-bound evidence',
    () async {
      for (final suite in [
        FirmwareHostSuite.authorityResources,
        FirmwareHostSuite.fieldResources,
      ]) {
        expect((await run(runner(), suite: suite))['status'], 'passed');
      }
      await expectLater(
        run(
          runner(root: 'bad-resource'),
          suite: FirmwareHostSuite.authorityResources,
        ),
        throwsFormatException,
      );
    },
  );

  test(
    'layout qualification requires measured source-bound coverage',
    () async {
      expect(
        (await run(
          runner(),
          suite: FirmwareHostSuite.authorityLayout,
        ))['status'],
        'passed',
      );
      await expectLater(
        run(
          runner(root: 'bad-layout'),
          suite: FirmwareHostSuite.authorityLayout,
        ),
        throwsFormatException,
      );
    },
  );

  test(
    'failed results and missing executables retain an interrupted request',
    () async {
      final failure = runner(root: 'failure');
      expect((await run(failure))['status'], 'failed');
      final missing = runner();
      await expectLater(
        run(missing, executable: '${temp.path}/missing'),
        throwsA(isA<ProcessException>()),
      );
      final history = await missing.history(account: account, python: python);
      expect(history.any((row) => row['status'] == 'incomplete'), isTrue);
      final pending = history.singleWhere(
        (row) => row['status'] == 'incomplete',
      );
      final exports = await Directory('${temp.path}/incomplete-exports')
          .create();
      final path = await missing.export(
        account: account,
        python: '${temp.path}/missing',
        attempt: pending['attempt'],
        directory: exports.path,
      );
      final bundle = jsonDecode(await File(path).readAsString()) as Map;
      expect(bundle['report']['status'], 'incomplete');
      expect(bundle['report']['id'], pending['attempt']);
      expect(bundle['report']['operator'], account);
      await expectLater(
        missing.export(
          account: account,
          python: python,
          attempt: pending['attempt'],
          directory: exports.path,
        ),
        throwsA(isA<FileSystemException>()),
      );
    },
  );

  test('invalid account, path, support and attempt fail closed', () async {
    await expectLater(run(runner(), user: '../other'), throwsFormatException);
    await expectLater(
      run(runner(), firmware: 'relative'),
      throwsFormatException,
    );
    await expectLater(
      run(runner(), firmware: '${temp.path}/missing-root'),
      throwsFormatException,
    );
    await expectLater(
      run(runner(), executable: 'relative'),
      throwsFormatException,
    );
    await expectLater(run(runner(script: 'changed')), throwsFormatException);
    await expectLater(run(runner(guide: 'changed')), throwsFormatException);
    await expectLater(
      run(runner(fingerprint: 'invalid')),
      throwsFormatException,
    );
    await expectLater(
      run(runner(protect: (_) async => false)),
      throwsA(isA<FileSystemException>()),
    );
    final checks = runner();
    await expectLater(
      checks.export(
        account: account,
        python: python,
        attempt: 'bad',
        directory: temp.path,
      ),
      throwsFormatException,
    );
    final wrongId = ProcessFirmwareChecks(
      firmwareRoot: '${temp.path}/fixture',
      evidenceRoot: Directory('${temp.path}/other'),
      adapter: adapter,
      definition: definition,
      newId: () => 'bad',
      workshopFingerprint: () async => 'c' * 64,
    );
    await expectLater(run(wrongId), throwsFormatException);
  });

  test(
    'altered or symlinked support and unreadable reports are rejected',
    () async {
      final checks = runner();
      final first = await run(checks);
      final folder = Directory('${temp.path}/evidence/$account/firmware-host');
      final support = File(
        '${folder.path}/adapter-${ProcessFirmwareChecks.adapterDigest}.py',
      );
      await support.writeAsString('changed');
      await expectLater(run(checks), throwsFormatException);
      await support.delete();
      await Link(support.path).create('${temp.path}/python');
      await expectLater(run(checks), throwsFormatException);
      await Link(support.path).delete();
      await File('${folder.path}/${first['attempt']}/completed.json').delete();
      final history = await checks.history(account: account, python: python);
      expect(history.single['status'], 'unreadable');
    },
  );

  test(
    'malformed, inconsistent and oversized runner output cannot pass',
    () async {
      for (final mode in [
        'bad-output',
        'nonobject',
        'inconsistent',
        'large',
        'missing-evidence',
        'bad-bindings',
        'bad-attempt',
        'bad-operator',
        'bad-suite',
        'bad-workshop',
        'bad-start',
        'missing-artifact',
        'bad-hash',
        'bad-baseline',
        'bad-report',
      ]) {
        await expectLater(
          run(runner(root: mode)),
          throwsA(isA<FormatException>()),
        );
      }
    },
  );

  test('corrupt saved requests are surfaced as unreadable', () async {
    final checks = runner();
    await expectLater(
      run(checks, executable: '${temp.path}/missing'),
      throwsA(isA<ProcessException>()),
    );
    final folder = Directory('${temp.path}/evidence/$account/firmware-host');
    final request = File(
      '${folder.path}/request-00000000-0000-4000-8000-000000000001.json',
    );
    await request.writeAsString('{broken');
    final history = await checks.history(account: account, python: python);
    expect(history.single['status'], 'unreadable');
  });

  test(
    'incomplete exports reject missing, redirected or mismatched evidence',
    () async {
      final checks = runner();
      await checks.history(account: account, python: python);
      const attempt = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
      final root = Directory('${temp.path}/evidence/$account/firmware-host');
      final exports = await Directory('${temp.path}/exports-safe').create();
      Future<String> export() => checks.export(
        account: account,
        python: python,
        attempt: attempt,
        directory: exports.path,
      );
      await expectLater(export(), throwsFormatException);
      final request = File('${root.path}/request-$attempt.json');
      await request.writeAsString(
        jsonEncode({'attempt': attempt, 'operator': 'other'}),
      );
      await expectLater(export(), throwsFormatException);
      await request.writeAsString(
        jsonEncode({'attempt': attempt, 'operator': account}),
      );
      final path = '${root.path}/$attempt';
      await Link(path).create(temp.path);
      await expectLater(export(), throwsFormatException);
      await Link(path).delete();
      await Directory(path).create();
      await Link('$path/started.json').create(request.path);
      await expectLater(export(), throwsFormatException);
      await Link('$path/started.json').delete();
      expect(await File(await export()).exists(), isTrue);
    },
  );

  test('a saved report with a different attempt ID is unreadable', () async {
    final checks = runner();
    final result = await run(checks);
    final file = File(
      '${temp.path}/evidence/$account/firmware-host/${result['attempt']}/completed.json',
    );
    final data = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    data['id'] = 'different';
    await file.writeAsString(jsonEncode(data));
    final history = await checks.history(account: account, python: python);
    expect(history.single['status'], 'unreadable');
  });

  test('a symlinked operator evidence folder is rejected', () async {
    final root = Directory('${temp.path}/evidence');
    final target = Directory('${temp.path}/redirect');
    await root.create();
    await target.create();
    await Link('${root.path}/$account').create(target.path);
    await expectLater(run(runner()), throwsFormatException);
    expect(await target.list().isEmpty, isTrue);
  });

  test('a nonresponsive adapter is terminated after the deadline', () async {
    final checks = runner(root: 'ignore', timeout: const Duration(seconds: 3));
    final expected = expectLater(run(checks), throwsA(isA<TimeoutException>()));
    final marker = File(
      '${temp.path}/evidence/$account/firmware-host/00000000-0000-4000-8000-000000000001/ready',
    );
    for (var i = 0; i < 200 && !await marker.exists(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    expect(
      await marker.exists(),
      isTrue,
      reason: 'The child must ignore SIGTERM before the deadline',
    );
    await expected;
  }, timeout: const Timeout(Duration(seconds: 15)));

  test('concurrent requests are blocked and cancellation retains a result', () async {
    final checks = runner(root: 'sleep');
    final pending = run(checks);
    final marker = File(
      '${temp.path}/evidence/$account/firmware-host/00000000-0000-4000-8000-000000000001/ready',
    );
    for (var i = 0; i < 100 && !await marker.exists(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    expect(await marker.exists(), isTrue);
    await expectLater(
      checks.history(account: account, python: python),
      throwsStateError,
    );
    await checks.cancel();
    expect((await pending)['status'], 'cancelled');
  });
}
