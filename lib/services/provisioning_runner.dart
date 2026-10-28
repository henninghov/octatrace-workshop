import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/ports.dart';
import '../domain/provisioning.dart';
import '../domain/registry.dart';

/// Thin process adapter; firmware owns USB, crypto, install guards and journal.
final class ProcessProvisioningRunner implements ProvisioningRunner {
  ProcessProvisioningRunner(
    this.firmwareRoot,
    this.evidenceRoot, {
    this.timeout = const Duration(seconds: 90),
    Future<Process> Function(String, List<String>)? startProcess,
  }) : _startProcess =
           startProcess ??
           ((path, args) => Process.start(path, args, runInShell: false));
  final String firmwareRoot;
  final Directory evidenceRoot;
  final Duration timeout;
  final Future<Process> Function(String, List<String>) _startProcess;
  Process? _process;
  bool _busy = false, _cancelled = false;
  static const pins = {
    "contracts/usb-provisioning/contract.json":
        "62414d301a437608c09f7693d06ad3167a6ae7f60d0c9e638153a0f98d0947c4",
    "contracts/usb-provisioning/proof.mjs":
        "e2738b810a1433190701788ed1940d7cb784702ef6af7f6c737ad6cc1fe292ab",
    "contracts/usb-provisioning/response.schema.json":
        "9e3af63f9b05ed41bb50011b134b7f7fa6d3d202b2df5203e568333a00c955e1",
    "contracts/usb-provisioning/vectors.json":
        "f4d7fd19a33e60883d60886c4ec10a46b1d37a2fde78a632038d902dabbc9361",
  };
  Future<void> verifyContract() async {
    final lock = jsonDecode(
      await File('$firmwareRoot/usb-provisioning.lock.json').readAsString(),
    ) as Map;
    final files = lock['files'];
    if (lock['version'] != 1 ||
        files is! Map ||
        files.length != pins.length ||
        pins.entries.any((e) => files[e.key] != e.value)) {
      throw const FormatException(
        'USB provisioning contract differs from Workshop',
      );
    }
    for (final entry in pins.entries) {
      if (sha256
              .convert(await File('$firmwareRoot/${entry.key}').readAsBytes())
              .toString() !=
          entry.value) {
        throw const FormatException('USB provisioning contract hash mismatch');
      }
    }
  }

  @override
  Future<Json> execute({
    required String account,
    required String command,
    Json parameters = const {},
  }) async {
    if (_busy) throw StateError('A provisioning step is already running');
    if (!RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
            .hasMatch(account) ||
        !{
          'inventory',
          'install',
          'identity',
          'provision',
          'inspect-storage',
          'prepare-storage',
        }.contains(command)) {
      throw const FormatException('Invalid provisioning request');
    }
    final args = ['-B', '$firmwareRoot/tools/provision.py', command];
    String? input;
    if (command == 'install' || command == 'identity') {
      final hardware = parameters['hardware'] as String;
      if (!hexId(hardware, 16)) {
        throw const FormatException('Invalid physical USB identity');
      }
      args.addAll(['--hardware', hardware]);
      if (command == 'identity') {
        final source = parameters['source'] as String;
        if (!hexId(source, 64)) {
          throw const FormatException('Invalid firmware source');
        }
        args.addAll(['--source', source]);
        if (parameters.containsKey('role')) {
          final role = parameters['role'];
          if (!{'Link', 'Core'}.contains(role)) {
            throw const FormatException('Invalid product role');
          }
          args.addAll(['--role', role as String]);
        }
      } else {
        args.addAll([
          '--manifest',
          parameters['manifest'] as String,
          '--volume',
          parameters['volume'] as String,
        ]);
      }
    }
    final storage =
        command == 'inspect-storage' || command == 'prepare-storage';
    if (command == 'provision' || storage) {
      // Only public server binding fields reach Python. Never send the session.
      input = jsonEncode({
        for (final key in [
          'request_id',
          'device_id',
          'serial',
          'article_id',
          'article_revision_id',
          'hardware',
          'source',
          'artifact',
          'challenge',
          'public_key',
          if (parameters.containsKey('role')) 'role',
          if (command == 'prepare-storage') 'inspection_token',
        ])
          key: parameters[key],
      });
      if (utf8.encode(input).length > 8192) {
        throw const FormatException('Provisioning input exceeds limit');
      }
    }
    if (storage) {
      args.addAll(['--manifest', parameters['manifest'] as String]);
      if (command == 'prepare-storage' &&
          (parameters['inspection_token'] is! String ||
              !hexId(parameters['inspection_token'] as String, 64))) {
        throw const FormatException('Current storage confirmation required');
      }
    }
    if (command == 'install' || command == 'provision' || storage) {
      args.addAll(['--evidence-root', '${evidenceRoot.path}/$account/usb']);
    }
    _busy = true;
    _cancelled = false;
    try {
      await verifyContract();
      if (_cancelled) throw BenchCancelled();
      final process = await _startProcess(
        '$firmwareRoot/build/bench-venv/bin/python',
        args,
      );
      _process = process;
      if (_cancelled) process.kill();
      Future<List<int>> capture(Stream<List<int>> stream) async {
        final bytes = <int>[];
        await for (final chunk in stream) {
          if (bytes.length + chunk.length > 65536) {
            process.kill();
            throw const FormatException('Runner output exceeds limit');
          }
          bytes.addAll(chunk);
        }
        return bytes;
      }

      final outputs = Future.wait<Object>([
        capture(process.stdout),
        capture(process.stderr),
        process.exitCode,
      ]);
      if (input != null) process.stdin.writeln(input);
      await process.stdin.close();
      final output = await outputs.timeout(
        timeout,
        onTimeout: () {
          process.kill(ProcessSignal.sigkill);
          throw TimeoutException(
            'Provisioning step timed out; retry the same reservation',
          );
        },
      );
      if (command != 'inventory') {
        final logs = await Directory(
          '${evidenceRoot.path}/$account/usb/adapter',
        ).create(recursive: true);
        final attempt = await logs.createTemp(
          'step-',
        ); // macOS mkdtemp: private mode 0700.
        await File('${attempt.path}/result.json').writeAsString(
          jsonEncode({
            'command': command,
            'exit_code': output[2],
            'stdout_base64': base64Encode(output[0] as List<int>),
            'stderr_base64': base64Encode(output[1] as List<int>),
          }),
          flush: true,
        );
      }
      if (_cancelled) throw BenchCancelled();
      if (output[2] != 0) {
        if (storage) {
          throw const ProvisioningFailure(
            'Identity storage preparation stopped. Keep this reservation and check the saved diagnostic, selected build and supported board profile. Leave the device in normal USB mode.',
          );
        }
        throw const ProvisioningFailure(
          'USB step failed. Keep this reservation, check the device and its firmware, then retry. For a new firmware install, put the device in USB bootloader mode and refresh.',
        );
      }
      final result = jsonDecode(utf8.decode(output[0] as List<int>));
      if (result is! Json) {
        throw const FormatException('Invalid provisioning report');
      }
      return result;
    } finally {
      _process = null;
      _busy = false;
    }
  }

  @override
  Future<void> cancel() async {
    _cancelled = true;
    final process = _process;
    if (process == null) return;
    process.kill();
    await process.exitCode.timeout(
      const Duration(seconds: 2),
      onTimeout: () {
        process.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
  }
}
