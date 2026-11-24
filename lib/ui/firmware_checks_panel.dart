import 'dart:async';

import 'package:flutter/material.dart';

import '../domain/firmware_checks.dart';
import '../domain/registry.dart';

class FirmwareChecksPanel extends StatefulWidget {
  const FirmwareChecksPanel({
    super.key,
    required this.checks,
    required this.account,
    required this.initialFirmware,
    required this.initialPython,
    required this.initialFonts,
  });
  final FirmwareChecks checks;
  final String account, initialFirmware, initialPython, initialFonts;

  @override
  State<FirmwareChecksPanel> createState() => _FirmwareChecksPanelState();
}

class _FirmwareChecksPanelState extends State<FirmwareChecksPanel> {
  late final TextEditingController firmware, python, fonts;
  final destination = TextEditingController();
  FirmwareHostSuite suite = FirmwareHostSuite.tooling;
  bool busy = false;
  String? message, selected;
  Json? report;
  List<Json> history = [];

  @override
  void initState() {
    super.initState();
    firmware = TextEditingController(text: widget.initialFirmware);
    python = TextEditingController(text: widget.initialPython);
    fonts = TextEditingController(text: widget.initialFonts);
  }

  @override
  void dispose() {
    unawaited(widget.checks.cancel());
    firmware.dispose();
    python.dispose();
    fonts.dispose();
    destination.dispose();
    super.dispose();
  }

  Future<void> run() async {
    setState(() {
      busy = true;
      message = null;
      report = null;
    });
    try {
      final value = await widget.checks.run(
        account: widget.account,
        suite: suite,
        firmwareRoot: firmware.text.trim(),
        python: python.text.trim(),
        fonts: fonts.text.trim(),
      );
      if (!mounted) return;
      setState(() {
        report = value;
        selected = value['attempt'] as String?;
        history = [
          value,
          ...history.where((entry) => entry['attempt'] != selected),
        ];
      });
    } catch (error) {
      if (mounted) setState(() => message = 'Test could not complete: $error');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> refresh() async {
    setState(() {
      busy = true;
      message = null;
    });
    try {
      final values = await widget.checks.history(
        account: widget.account,
        python: python.text.trim(),
      );
      if (!mounted) return;
      setState(() {
        history = values;
        selected = values.isEmpty ? null : values.first['attempt'] as String?;
        report = values.isEmpty ? null : values.first;
      });
    } catch (error) {
      if (mounted) {
        setState(() => message = 'Reports could not be opened: $error');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> export() async {
    final attempt = selected;
    if (attempt == null) return;
    setState(() {
      busy = true;
      message = null;
    });
    try {
      final path = await widget.checks.export(
        account: widget.account,
        python: python.text.trim(),
        attempt: attempt,
        directory: destination.text.trim(),
      );
      if (mounted) setState(() => message = 'Exported report: $path');
    } catch (error) {
      if (mounted) {
        setState(() => message = 'Report could not be exported: $error');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => ExpansionTile(
    title: const Text('Firmware host regression tests'),
    subtitle: const Text(
      'Runs on this Mac; does not establish a device or physical result.',
    ),
    children: [
      TextField(
        key: const ValueKey('firmware-test-root'),
        controller: firmware,
        enabled: !busy,
        decoration: const InputDecoration(
          labelText: 'Firmware checkout folder',
        ),
      ),
      TextField(
        key: const ValueKey('firmware-test-python'),
        controller: python,
        enabled: !busy,
        decoration: const InputDecoration(
          labelText: 'Python test environment executable',
        ),
      ),
      TextField(
        key: const ValueKey('firmware-test-fonts'),
        controller: fonts,
        enabled: !busy,
        decoration: const InputDecoration(
          labelText: 'Licensed firmware font directory',
        ),
      ),
      DropdownButton<FirmwareHostSuite>(
        key: const ValueKey('firmware-test-suite'),
        value: suite,
        isExpanded: true,
        items: const [
          DropdownMenuItem(
            value: FirmwareHostSuite.tooling,
            child: Text('Firmware tooling regression'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.host,
            child: Text('Firmware native host regression'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.authorityStorage,
            child: Text('Authority storage qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.claimQr,
            child: Text('Claim QR qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.deviceAuthority,
            child: Text('Device authority qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.deviceCredential,
            child: Text('Device credential qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.fieldHandshake,
            child: Text('Field handshake metadata qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.proofContext,
            child: Text('Proof context qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.setupTransfer,
            child: Text('Setup transfer qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.sessionControl,
            child: Text('Session control qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.authorityResources,
            child: Text('Authority resources qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.fieldResources,
            child: Text('Field resources qualification'),
          ),
          DropdownMenuItem(
            value: FirmwareHostSuite.authorityLayout,
            child: Text('Authority layout qualification'),
          ),
        ],
        onChanged: busy
            ? null
            : (value) {
                if (value != null) setState(() => suite = value);
              },
      ),
      if (suite == FirmwareHostSuite.fieldResources)
        const Text(
          'Requires current LINK and CORE builds. This run first repeats the native host tests.',
        ),
      if (suite == FirmwareHostSuite.authorityResources)
        const Text(
          'Requires a current LINK build and reviewed compiler inputs.',
        ),
      if (suite == FirmwareHostSuite.authorityLayout)
        const Text(
          'Requires current LINK and CORE builds. This run measures tooling tests and makes a separate LINK build.',
        ),
      Wrap(
        spacing: 12,
        children: [
          FilledButton(
            onPressed: busy ? null : run,
            child: const Text('Run firmware tests'),
          ),
          OutlinedButton(
            onPressed: busy ? null : refresh,
            child: const Text('Reopen reports'),
          ),
          if (busy)
            OutlinedButton(
              onPressed: widget.checks.cancel,
              child: const Text('Cancel'),
            ),
        ],
      ),
      if (busy) const LinearProgressIndicator(),
      if (history.isNotEmpty)
        DropdownButton<String>(
          key: const ValueKey('firmware-test-history'),
          value: selected,
          isExpanded: true,
          items: [
            for (final item in history)
              DropdownMenuItem(
                value: item['attempt'] as String,
                child: Text(
                  '${item['suite'] ?? 'Unknown suite'} · ${item['status']} · ${item['attempt']}',
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: busy
              ? null
              : (value) => setState(() {
                  selected = value;
                  report = history
                      .where((entry) => entry['attempt'] == value)
                      .firstOrNull;
                }),
        ),
      if (report != null) ...[
        Text('Status: ${report!['status']}'),
        Text('Suite: ${report!['suite'] ?? 'Unknown'}'),
        Text('Attempt: ${report!['attempt']}'),
        if (report!['operator'] != null)
          SelectableText('Operator: ${report!['operator']}'),
        if (report!['firmware_source_id'] != null)
          SelectableText('Firmware source: ${report!['firmware_source_id']}'),
        if (report!['workshop_fingerprint'] != null)
          SelectableText('Workshop build: ${report!['workshop_fingerprint']}'),
        if (report!['reason'] != null) Text('Reason: ${report!['reason']}'),
        TextField(
          key: const ValueKey('firmware-test-export-folder'),
          controller: destination,
          enabled: !busy,
          decoration: const InputDecoration(
            labelText: 'Existing export folder',
          ),
        ),
        OutlinedButton(
          onPressed: busy || selected == null ? null : export,
          child: const Text('Export selected report'),
        ),
      ],
      if (message != null) SelectableText(message!),
    ],
  );
}
