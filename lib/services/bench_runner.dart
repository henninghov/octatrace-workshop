import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../domain/registry.dart';
import '../domain/ports.dart';
export '../domain/ports.dart' show BenchRunner;

/// Executes the firmware-owned CLI; USB codecs and assertions stay in Python.
final class ProcessBenchRunner implements BenchRunner {
  ProcessBenchRunner(
    this.firmwareRoot, {
    this.timeout = const Duration(seconds: 60),
  });
  final String firmwareRoot;
  final Duration timeout;
  Process? _process;
  bool _busy = false;
  bool _cancelled = false;
  static const commands = {'identity', 'status', 'tests', 'test-all', 'check'};

  Future<void> verifyContract() async {
    final root = Directory(firmwareRoot).absolute.path;
    final lockFile = File('$root/usb-bench.lock.json');
    final lock = jsonDecode(await lockFile.readAsString()) as Map;
    if (lock['version'] != 1 || lock['files'] is! Map) {
      throw const FormatException('Unsupported USB contract lock');
    }
    // Consumer pin, not a lock dynamically trusted from an arbitrary checkout.
    const expected = {
      'contracts/usb-bench/contract.json':
          '5c1471adb7311e1b2a4d25088f02786a1cbeca3c3eb8b480d137f30b7ef31cf1',
      'contracts/usb-bench/response.schema.json':
          'f78872034e7d260f6df5d44527e106b4e78f4c75312c8852c9b8fad6b8117e34',
      'contracts/usb-bench/vectors.json':
          'd52df8079b91261c1c8322214931cf236fba715e61f9ba0e31569e3baf641336',
    };
    final files = lock['files'] as Map;
    if (files.length != expected.length ||
        expected.entries.any((entry) => files[entry.key] != entry.value)) {
      throw const FormatException('USB contract differs from the Workshop pin');
    }
    for (final entry in expected.entries) {
      final bytes = await File('$root/${entry.key}').readAsBytes();
      if (sha256.convert(bytes).toString() != entry.value) {
        throw const FormatException('USB contract hash mismatch');
      }
    }
  }

  @override
  Future<Json> run({
    required String port,
    required String role,
    required String build,
    required String command,
  }) async {
    if (_busy) throw StateError('A device operation is already running');
    if (!commands.contains(command) ||
        !{'Link', 'Core'}.contains(role) ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(build) ||
        !RegExp(r'^/dev/cu\.usbmodem[\w.-]+$').hasMatch(port)) {
      throw const FormatException(
        'Choose a USB port, role and full build fingerprint',
      );
    }
    _busy = true;
    _cancelled = false;
    try {
      await verifyContract();
      final process = await Process.start(
        '$firmwareRoot/build/bench-venv/bin/python',
        [
          '-B',
          '$firmwareRoot/tools/bench.py',
          command,
          '--port',
          port,
          '--expect-role',
          role,
          '--expect-build',
          build,
        ],
        runInShell: false,
      );
      _process = process;
      if (_cancelled) process.kill();
      Future<List<int>> capture(Stream<List<int>> stream) async {
        final bytes = <int>[];
        await for (final chunk in stream) {
          if (bytes.length + chunk.length > 65536) {
            process.kill();
            throw const FormatException('Runner output limit exceeded');
          }
          bytes.addAll(chunk);
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
            onTimeout: () {
              process.kill(ProcessSignal.sigkill);
              throw TimeoutException('Runner deadline exceeded');
            },
          );
      if (_cancelled) throw BenchCancelled();
      if (output[2] != 0) {
        throw StateError('Shared runner failed; inspect the target and build');
      }
      final json = jsonDecode(utf8.decode(output[0] as List<int>));
      if (json is! Map<String, dynamic>) {
        throw const FormatException('Invalid runner report');
      }
      return json;
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
