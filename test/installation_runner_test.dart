import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/domain/bench_definition.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/ports.dart';
import 'package:octatrace_workshop/domain/provisioning.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/services/provisioning_runner.dart';

import 'provisioning_test.dart' as usb;
import 'widget_test.dart' as f;

const installationAttempt = '60000000-0000-4000-8000-000000000006';
const interactiveHelper = '''import sys,json,time
review,result,mode=json.loads(sys.argv[1])
request=json.loads(sys.stdin.readline())
assert 'access_token' not in request
if mode.startswith('raw:'):
 print(mode[4:],flush=True);time.sleep(.1);sys.exit(0)
print(json.dumps({'event':'review','data':review}),flush=True)
if mode=='die':sys.exit(1)
if mode=='timeout':time.sleep(10)
answer=json.loads(sys.stdin.readline())
assert answer['review_token']==review['review_token']
if not answer['confirm']:result['cancelled']=True;result['passed']=False
print(json.dumps({'event':'result','data':result}),flush=True)
''';

class InstallationProcessFixture {
  InstallationProcessFixture(
    this.root, {
    this.preparation = false,
    this.fault = 0,
  });
  final Directory root;
  final bool preparation;
  final int fault;
  final key = '04${'11' * 64}';
  late ProvisionedIdentityRead read;
  late PublicFactoryCredential credential;
  late Json review, result;
  String mode = 'success';
  Duration timeout = const Duration(seconds: 5);
  late ProcessProvisioningRunner runner;
  Json? diagnostic;
  Future<void> init() async {
    final guide = BenchDefinition.fromSnapshot(
      File(
        preparation
            ? BenchDefinition.preparationAsset
            : fault == 1
            ? BenchDefinition.intentStopAsset
            : BenchDefinition.installationAsset,
      ).readAsStringSync(),
    );
    final build = guide.builds.firstWhere((b) => b.role == 'Link');
    read = guide.admit(
      device: DeviceRecord.fromJson({
        'id': f.device,
        'serial': 'D000000000123',
        'article_revision_id': f.revision,
        'provisioning_state': 'provisioned',
        'hardware_uid': usb.hardware,
      }),
      article: ArticleRevision.fromJson({
        'id': f.revision,
        'article_id': f.other,
        'code': 'TEST',
        'name': 'Board',
        'role': 'Link',
        'revision': 1,
        'case_version': 'A',
        'parts': [],
      }),
      target: UsbTarget.fromJson(usb.targetJson()),
      build: build,
    );
    credential = PublicFactoryCredential.fromJson(
      {
        'v': 1,
        'device_id': f.device,
        'role': 'Link',
        'credential': '010203',
        'credential_sha256': sha256.convert([1, 2, 3]).toString(),
      },
      deviceId: f.device,
      role: 'Link',
      expectedDigest: sha256.convert([1, 2, 3]).toString(),
    );
    final identity = <String, dynamic>{
      'v': 1,
      'ok': true,
      'type': 'identity',
      'algorithm': 'P256-SHA256',
      'state': 'ready',
      'busy': false,
      'failed': false,
      'device_id': f.device,
      'serial': read.device.serial,
      'article_id': f.other,
      'article_revision_id': f.revision,
      'role': 'Link',
      'build': build.source,
      'hardware': usb.hardware,
      'boot': '22' * 16,
      'public_key': key,
      'challenge': '33' * 32,
      'signature': '44' * 64,
    };
    if (preparation) {
      final inspected = <String, dynamic>{
        'v': 1,
        'id': 9,
        'ok': true,
        'type': 'credential_storage',
        'role': 'Link',
        'build': build.source,
        'hardware': usb.hardware,
        'boot': '22' * 16,
        'state': 'unknown',
        'busy': false,
        'failed': false,
        'last_request': 8,
        'sha256': '55' * 32,
        'identity_proof': identity,
      };
      review = {
        'inspection': inspected,
        'attempt_id': installationAttempt,
        'review_token': 'aa' * 32,
        'expires_ms': 25000,
      };
      final prepared = {
        ...inspected,
        'state': 'blank',
        'id': 11,
        'last_request': 10,
        'sha256': sha256.convert(List<int>.filled(8192, 255)).toString(),
      }..remove('identity_proof');
      result = {
        'inspection': inspected,
        'attempt_id': installationAttempt,
        'preparation_result': prepared,
        'cancelled': false,
        'passed': true,
      };
    } else {
      final delivery = <String, dynamic>{
        'v': 1,
        'id': 9,
        'ok': true,
        'type': 'credential_delivery',
        'role': 'Link',
        'build': build.source,
        'boot': '22' * 16,
        'hardware': usb.hardware,
        'device_id': f.device,
        'serial': read.device.serial,
        'article_id': f.other,
        'article_revision_id': f.revision,
        'transfer_id': 1,
        'challenge': '55' * 32,
        'credential_revision': 1,
        'content_id': '66' * 32,
        'envelope_sha256': credential.digest,
        'signature': '77' * 64,
      };
      final proof = {
        ...delivery,
        'type': 'credential_installation',
        'result': 'review',
        'journal_state': 'empty',
        'slots_used': 0,
        'journal_revision': 0,
        'journal_content_id': '0' * 64,
        'fault': fault,
      };
      review = {
        'identity_proof': identity,
        'delivery_proof': delivery,
        'review': proof,
        'attempt_id': installationAttempt,
        'review_token': 'aa' * 32,
        'expires_ms': 25000,
      };
      result = {
        'identity_proof': identity,
        'delivery_proof': delivery,
        'review': proof,
        'attempt_id': installationAttempt,
        'installation_proof': {
          ...proof,
          'result': fault == 1 ? 'interrupted' : 'installed',
          'journal_state': fault == 1 ? 'pending' : 'ready',
          'slots_used': 1,
          'journal_revision': fault == 1 ? 0 : 1,
          'journal_content_id': fault == 1 ? '0' * 64 : delivery['content_id'],
        },
        'cancelled': false,
        'passed': true,
      };
    }
    for (final lock in [
      'usb-provisioning.lock.json',
      'control-storage.lock.json',
    ]) {
      await File('vendor/$lock').copy('${root.path}/$lock');
    }
    final pins = {
      ...ProcessProvisioningRunner.pins,
      ...ProcessProvisioningRunner.controlPins,
      ...guide.runnerFiles,
    };
    runner = ProcessProvisioningRunner(
      root.path,
      Directory('${root.path}/evidence'),
      timeout: timeout,
      fileDigest: (file) async =>
          pins[file.path.substring(root.path.length + 1)]!,
      startProcess: (_, args) {
        expect(
          args,
          contains(
            '${root.path}/tools/credential_${preparation ? 'preparation' : 'installation'}.py',
          ),
        );
        return Process.start('/usr/bin/python3', [
          '-c',
          interactiveHelper,
          jsonEncode([review, result, mode]),
        ]);
      },
    );
  }

  Future<Json> run([Future<Json> Function(Json)? confirm]) {
    Future<Json> approve(Json value) async => {
      'confirm': true,
      'review_token': value['review_token'],
    };
    return preparation
        ? runner.readBenchPreparation(
            f.actor,
            read,
            key,
            installationAttempt,
            confirm ?? approve,
            onDiagnostic: (value) => diagnostic = value,
          )
        : runner.readBenchInstallation(
            f.actor,
            read,
            key,
            credential,
            installationAttempt,
            fault,
            confirm ?? approve,
            onDiagnostic: (value) => diagnostic = value,
          );
  }
}

void main() {
  late Directory root;
  late InstallationProcessFixture fixture;
  setUp(() async {
    root = await Directory.systemTemp.createTemp(
      'workshop-installation-process-',
    );
    fixture = InstallationProcessFixture(root);
    await fixture.init();
  });
  tearDown(() async => root.delete(recursive: true));
  test('interactive owner process waits for distinct approval and saves public diagnostics', () async {
    final result = await fixture.run((review) async {
      expect(review['review']['envelope_sha256'], fixture.credential.digest);
      return {'confirm': true, 'review_token': review['review_token']};
    });
    expect(result, fixture.result);
    expect(fixture.diagnostic!['exit_code'], 0);
    expect(
      utf8.decode(base64Decode(fixture.diagnostic!['stdout_base64'])),
      isNot(contains('010203')),
    );
  });
  test('controlled stop returns pending rather than installed', () async {
    fixture = InstallationProcessFixture(root, fault: 1);
    await fixture.init();
    expect(
      (await fixture.run())['installation_proof']['journal_state'],
      'pending',
    );
  });
  test('preparation uses its independent inspection-bound runner', () async {
    fixture = InstallationProcessFixture(root, preparation: true);
    await fixture.init();
    expect((await fixture.run())['preparation_result']['state'], 'blank');
  });
  for (final preparation in [false, true]) {
    test(
      '${preparation ? 'preparation' : 'installation'} explicit cancellation never reports a pass',
      () async {
        fixture = InstallationProcessFixture(root, preparation: preparation);
        await fixture.init();
        await expectLater(
          fixture.run(
            (review) async => {
              'confirm': false,
              'review_token': review['review_token'],
            },
          ),
          throwsA(isA<BenchCancelled>()),
        );
      },
    );
  }
  for (final change in <Json>[
    {'attempt_id': f.other},
    {'review_token': 'bad'},
    {'expires_ms': 0},
    {'extra': true},
    {'expires_ms': 25001},
  ]) {
    test(
      'invalid installation confirmation $change fails before approval',
      () async {
        fixture.review = {...fixture.review, ...change};
        var approved = false;
        await expectLater(
          fixture.run((value) async {
            approved = true;
            return {};
          }),
          throwsA(isA<ProvisioningFailure>()),
        );
        expect(approved, false);
        expect(fixture.diagnostic, isNotNull);
      },
    );
  }
  for (final change in <Json>[
    {'fault': 1},
    {'boot': 'ff' * 16},
    {'slots_used': 10},
    {'signature': '0' * 128},
    {'journal_state': 'unavailable'},
    {'result': 'installed'},
    {'extra': true},
  ]) {
    test('review proof $change cannot reach confirmation', () async {
      fixture.review = {
        ...fixture.review,
        'review': {...fixture.review['review'], ...change},
      };
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
    });
  }
  for (final change in <Json>[
    {'passed': false},
    {'attempt_id': f.other},
    {'extra': true},
    {'installation_proof': {}},
    {'review': {}},
  ]) {
    test('invalid installation result $change remains failed', () async {
      fixture.result = {...fixture.result, ...change};
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
    });
  }
  for (final state in ['interrupted', 'recognizable', 'blank']) {
    test('preparation preserves $state records', () async {
      fixture = InstallationProcessFixture(root, preparation: true);
      await fixture.init();
      fixture.review['inspection']['state'] = state;
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
    });
  }
  test(
    'preparation malformed review, changed result and blank digest fail closed',
    () async {
      fixture = InstallationProcessFixture(root, preparation: true);
      await fixture.init();
      final original = jsonDecode(jsonEncode(fixture.review)) as Json;
      fixture.review['review_token'] = 'bad';
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
      fixture.review = original;
      fixture.result['passed'] = false;
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
      fixture.result['passed'] = true;
      fixture.result['preparation_result']['sha256'] = 'ff' * 32;
      await expectLater(fixture.run(), throwsA(isA<ProvisioningFailure>()));
    },
  );
  for (final value in [
    '[]',
    '{"event":"review","data":{}}\n{"event":"review","data":{}}',
    '{"event":"result","data":{}}',
    '{"event":"unknown","data":{}}',
    '{"event":"review","data":{},"extra":1}',
    '{"event":"review","data":[]}',
    '{bad',
  ]) {
    test('malformed or reordered event is retained: $value', () async {
      fixture.mode = 'raw:$value';
      await expectLater(fixture.run(), throwsA(isA<Exception>()));
      expect(fixture.diagnostic, isNotNull);
    });
  }
  test('truncated event has retained failure evidence', () async {
    fixture.mode = 'raw:';
    await expectLater(fixture.run(), throwsFormatException);
    expect(fixture.diagnostic, isNotNull);
  });
  test(
    'oversized interactive output is bounded and retained as failed',
    () async {
      fixture.mode = 'raw:${'x' * 65537}';
      await expectLater(fixture.run(), throwsFormatException);
      expect(
        base64Decode(fixture.diagnostic!['stdout_base64']).length,
        lessThanOrEqualTo(65536),
      );
    },
  );
  test('runner expiry releases the process before a late answer', () async {
    fixture.mode = 'die';
    final ready = Completer<void>(), answer = Completer<Json>();
    final run = fixture.run((review) {
      ready.complete();
      return answer.future;
    });
    await ready.future;
    await expectLater(run, throwsA(isA<ProvisioningFailure>()));
    answer.complete({'confirm': true, 'review_token': 'aa' * 32});
    await Future<void>.delayed(Duration.zero);
    fixture.mode = 'success';
    expect((await fixture.run())['passed'], true);
  });
  test(
    'cancel during review retains diagnostic and ignores late approval',
    () async {
      final ready = Completer<void>(), answer = Completer<Json>();
      final run = fixture.run((review) {
        ready.complete();
        return answer.future;
      });
      await ready.future;
      final failed = expectLater(run, throwsA(isA<BenchCancelled>()));
      await fixture.runner.cancel();
      await failed;
      answer.complete({'confirm': true, 'review_token': 'aa' * 32});
      await Future<void>.delayed(Duration.zero);
      expect(fixture.diagnostic, isNotNull);
    },
  );
  test(
    'callback save failure kills the child and retains bounded evidence',
    () async {
      await expectLater(
        fixture.run(
          (review) async => throw const FileSystemException('Disk full'),
        ),
        throwsA(isA<FileSystemException>()),
      );
      expect(fixture.diagnostic, isNotNull);
    },
  );
  test(
    'timeout saves diagnostic and no late confirmation enters a new process',
    () async {
      fixture = InstallationProcessFixture(root)
        ..timeout = const Duration(milliseconds: 100);
      await fixture.init();
      fixture.mode = 'timeout';
      await expectLater(fixture.run(), throwsA(isA<TimeoutException>()));
      expect(fixture.diagnostic, isNotNull);
    },
  );
}
