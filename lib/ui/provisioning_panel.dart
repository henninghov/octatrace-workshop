import 'dart:convert';

import 'package:flutter/material.dart';

import '../domain/registry.dart';
import '../domain/provisioning.dart';
import '../domain/workshop_controller.dart';
import 'copyable_text.dart';

class ProvisioningPanel extends StatefulWidget {
  const ProvisioningPanel({
    super.key,
    required this.controller,
    required this.device,
    required this.article,
  });
  final WorkshopController controller;
  final DeviceRecord device;
  final ArticleRevision? article;
  @override
  State<ProvisioningPanel> createState() => _ProvisioningPanelState();
}

class _ProvisioningPanelState extends State<ProvisioningPanel> {
  String? targetKey, source;
  Future<bool> _confirmPreparation(StoragePreparation preparation) async {
    if (!mounted) return false;
    final accepted = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dialog) => AlertDialog(
        title: const Text('Prepare identity storage'),
        content: SizedBox(
          width: 480,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              CopyableText(label: 'Device serial', value: preparation.serial),
              const SizedBox(height: 12),
              Text(preparation.boardName),
              const SizedBox(height: 12),
              Text(
                'Prepare the reserved identity area (${preparation.bytes} bytes) for this device.',
              ),
              const SizedBox(height: 12),
              const Text(
                'This deletes its unknown contents. Existing identities are protected. Firmware, bootloader and Bluetooth bond storage are preserved.',
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialog, false),
            child: const Text('Keep unchanged'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialog, true),
            child: const Text('Prepare and continue'),
          ),
        ],
      ),
    );
    return mounted && accepted == true;
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.controller, device = widget.device;
    final inventory = c.usbInventory;
    final target = inventory?.targets
        .where((t) => t.key == targetKey)
        .firstOrNull;
    final product = widget.article?.role.toUpperCase() ?? 'device';
    final builds =
        inventory?.builds
            .where((b) => b.role == widget.article?.role)
            .toList() ??
        [];
    final firmware = builds.where((b) => b.key == source).firstOrNull;
    final eligible =
        {'Link', 'Core'}.contains(widget.article?.role) &&
        device.serial.startsWith('D') &&
        device.ownerId == null &&
        device.state != 'retired';
    final matches =
        target == null ||
        device.hardwareUid == null ||
        device.hardwareUid == target.hardware;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (!eligible)
          const CopyableText(
            label: 'Message',
            value: 'Choose an unclaimed development LINK or CORE device.',
          ),
        const Text(
          '1. Choose the device and firmware.  2. Install and verify.  3. Confirm the registry.',
        ),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: c.busy ? null : c.discoverUsb,
          icon: const Icon(Icons.refresh, size: 18),
          label: const Text('Refresh USB and firmware'),
        ),
        const SizedBox(height: 16),
        if (inventory == null)
          CopyableText(
            label: 'Message',
            value:
                'Connect $product by USB, then refresh. To install new firmware, use its usual USB bootloader mode.',
          ),
        if (inventory != null) ...[
          if (inventory.targets.isEmpty)
            const CopyableText(
              label: 'Message',
              value: 'No supported USB device found. For a first installation, enter USB bootloader mode and refresh.',
            ),
          DropdownButtonFormField<String>(
            key: ValueKey('usb-$targetKey-${target?.key}'),
            initialValue: target?.key,
            isExpanded: true,
            decoration: const InputDecoration(
              labelText: 'Connected USB device',
            ),
            items: inventory.targets
                .map(
                  (t) => DropdownMenuItem(
                    value: t.key,
                    child: Text(t.label, overflow: TextOverflow.ellipsis),
                  ),
                )
                .toList(),
            onChanged: c.busy
                ? null
                : (value) => setState(() => targetKey = value),
          ),
          const SizedBox(height: 16),
          if (builds.isEmpty)
            CopyableText(
              label: 'Message',
              value:
                  'No qualified $product firmware build found. Complete the development build and validation first.',
            ),
          DropdownButtonFormField<String>(
            key: ValueKey('firmware-$source-${firmware?.key}'),
            initialValue: firmware?.key,
            isExpanded: true,
            decoration: const InputDecoration(
              labelText: 'Validated firmware build',
            ),
            items: builds
                .map(
                  (b) => DropdownMenuItem(
                    value: b.key,
                    child: Text(b.label, overflow: TextOverflow.ellipsis),
                  ),
                )
                .toList(),
            onChanged: c.busy
                ? null
                : (value) => setState(() => source = value),
          ),
          const SizedBox(height: 16),
        ],
        if (target != null && target.mode == 'app')
          const CopyableText(
            label: 'Message',
            value: 'Normal USB mode: finish or verify an existing installation. For a new firmware install, enter USB bootloader mode and refresh.',
          ),
        if (!matches)
          const CopyableText(
            label: 'Message',
            value: 'This reservation is bound to another USB device. Select the matching device.',
          ),
        if (c.provisioningStage != null)
          CopyableText(label: 'Progress', value: c.provisioningStage!),
        const SizedBox(height: 12),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            FilledButton(
              onPressed:
                  c.busy ||
                      !eligible ||
                      !matches ||
                      target == null ||
                      firmware == null
                  ? null
                  : () => c.provision(
                      device,
                      widget.article!,
                      target,
                      firmware,
                      confirmPreparation: _confirmPreparation,
                    ),
              child: Text(
                target?.mode == 'bootloader'
                    ? 'Install and provision'
                    : 'Verify and provision',
              ),
            ),
            if (c.busy)
              OutlinedButton(onPressed: c.cancel, child: const Text('Cancel')),
            if (c.pendingEvidence > 0)
              OutlinedButton(
                onPressed: c.busy ? null : c.syncEvidence,
                child: const Text('Retry evidence upload'),
              ),
          ],
        ),
        const SizedBox(height: 16),
        if (c.provisioningDeviceId == device.id &&
            c.provisioningOutcome != null)
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: CopyableText(
                  label: 'Server confirmation',
                  value: c.provisioningOutcome == ProvisioningOutcome.successful
                      ? 'Provisioning confirmed by the server. Registry refreshed.'
                      : c.readbackDeviceId == device.id && c.readback != null
                      ? 'Proof saved locally. Registry confirmation is pending; retry the upload.'
                      : c.provisioningOutcome == ProvisioningOutcome.failed
                      ? 'Provisioning failed. Keep this reservation and review the diagnostic.'
                      : 'Provisioning is pending. Registry confirmation has not completed.',
                ),
              ),
              const SizedBox(width: 12),
              ProvisioningStatusPill(outcome: c.provisioningOutcome!),
            ],
          ),
        ExpansionTile(
          title: const Text('Details'),
          tilePadding: EdgeInsets.zero,
          children: [
            if (device.hardwareUid != null)
              CopyableText(
                label: 'Registered USB identity',
                value: device.hardwareUid!,
              ),
            if (target != null)
              CopyableText(
                label: 'Selected USB identity',
                value: target.hardware,
              ),
            if (firmware != null) ...[
              CopyableText(label: 'Firmware source', value: firmware.source),
              CopyableText(
                label: 'Firmware artifact',
                value: firmware.artifact,
              ),
            ],
            if (c.readbackDeviceId == device.id && c.readback != null)
              CopyableText(
                label: 'Verification evidence',
                value: const JsonEncoder.withIndent('  ').convert(c.readback),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
          ],
        ),
      ],
    );
  }
}

class ProvisioningStatusPill extends StatelessWidget {
  const ProvisioningStatusPill({super.key, required this.outcome});
  final ProvisioningOutcome outcome;
  @override
  Widget build(BuildContext context) {
    final (foreground, background) = switch (outcome) {
      ProvisioningOutcome.successful => (
        const Color(0xff1b5e20),
        const Color(0xffe8f5e9),
      ),
      ProvisioningOutcome.pending => (
        const Color(0xffe65100),
        const Color(0xfffff3e0),
      ),
      ProvisioningOutcome.failed => (
        const Color(0xffb71c1c),
        const Color(0xffffebee),
      ),
    };
    return DecoratedBox(
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Text(
          outcome.name.toUpperCase(),
          style: TextStyle(
            color: foreground,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }
}
