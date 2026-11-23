import 'package:flutter/material.dart';

import '../domain/claimed_update.dart';
import '../domain/registry.dart';
import '../domain/workshop_controller.dart';

/// A supervised development-only application update; no provisioning actions.
class ClaimedUpdatePanel extends StatefulWidget {
  const ClaimedUpdatePanel({
    super.key,
    required this.controller,
    required this.device,
    required this.article,
  });
  final WorkshopController controller;
  final DeviceRecord device;
  final ArticleRevision article;

  @override
  State<ClaimedUpdatePanel> createState() => _ClaimedUpdatePanelState();
}

class _ClaimedUpdatePanelState extends State<ClaimedUpdatePanel> {
  ClaimedUpdateSession? session;
  String? detail;
  bool operatorReady = false;
  final folder = TextEditingController();
  String? exported;

  @override
  void dispose() {
    folder.dispose();
    super.dispose();
  }

  Future<void> _action(Future<void> Function() operation) async {
    final c = widget.controller;
    setState(() => detail = null);
    await c.action(
      operation,
      refreshRegistry: false,
      onError: (error) {
        if (mounted) setState(() => detail = error.toString());
      },
    );
    if (mounted) setState(() {});
  }

  Future<void> _start() async {
    final c = widget.controller;
    final account = c.gateway.accountId;
    if (account == null) return;
    final next = c.claimedUpdateFactory!(
      account,
      widget.device,
      widget.article,
      () =>
          mounted && c.access == Access.ready && c.gateway.accountId == account,
    );
    setState(() => session = next);
    await _action(() async {
      if (!await next.checkPending()) {
        await next.preflight(operatorReady: operatorReady);
      }
    });
  }

  Future<void> _confirm() async {
    final target = session!.report!['after_source'] as String;
    final accepted = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dialog) => AlertDialog(
        title: const Text('Confirm CORE firmware update'),
        content: Text(
          'Update ${widget.device.serial} to CORE build ${target.substring(0, 8)}. '
          'Connect only this CORE and select its USB bootloader. '
          'The application firmware will be replaced. The update does not '
          'provision, change ownership or intentionally erase identity, keys, '
          'bonds or reserved storage. Keep the device connected until the '
          'identity is checked after reboot.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialog, false),
            child: const Text('Keep unchanged'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialog, true),
            child: const Text('Confirm firmware update'),
          ),
        ],
      ),
    );
    if (accepted == true && mounted) {
      await _action(() => session!.install(confirmed: true));
    }
  }

  @override
  Widget build(BuildContext context) {
    final phase = session?.phase ?? 'new';
    final saved = session?.report ?? session?.priorPending;
    final c = widget.controller;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Firmware update', style: TextStyle(fontSize: 20)),
        const SizedBox(height: 8),
        const Text(
          'This supervised CORE test-image update preserves the existing claim. '
          'Connect only this CORE in normal USB mode before verifying its identity.',
        ),
        const SizedBox(height: 12),
        if (phase == 'new' ||
            phase == 'preflight_failed' ||
            phase == 'cancelled_before_write') ...[
          CheckboxListTile(
            value: operatorReady,
            onChanged: c.busy
                ? null
                : (value) => setState(() => operatorReady = value == true),
            title: const Text(
              'CORE is stopped, retained work is saved, USB power is stable, and only this CORE is connected.',
            ),
          ),
          FilledButton(
            onPressed: c.busy || !operatorReady ? null : _start,
            child: const Text('Verify CORE identity for update'),
          ),
        ],
        if (phase == 'awaiting_bootloader') ...[
          const Text(
            'Identity verified. Quickly press RST twice to enter the Heltec '
            'USB bootloader, then review and confirm the firmware update.',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              FilledButton(
                onPressed: c.busy ? null : _confirm,
                child: const Text('Review firmware update'),
              ),
              OutlinedButton(
                onPressed: c.busy
                    ? null
                    : () => _action(session!.cancelBeforeWrite),
                child: const Text('Cancel before update'),
              ),
            ],
          ),
        ],
        if (phase == 'write_started' || phase == 'awaiting_postflight')
          const Text('Updating and checking identity. Keep CORE connected.'),
        if (phase == 'verified')
          RepaintBoundary(
            key: const ValueKey('claimed-update-success'),
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Theme.of(context).brightness == Brightness.dark
                    ? const Color(0xff20382d)
                    : const Color(0xffe7f5eb),
                border: Border.all(
                  color: Theme.of(context).brightness == Brightness.dark
                      ? const Color(0xff4b8060)
                      : const Color(0xffa3c9ae),
                ),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.check_circle_outline,
                    color: Theme.of(context).brightness == Brightness.dark
                        ? const Color(0xffa3dfb8)
                        : const Color(0xff286b40),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Update successful',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'CORE build ${(saved!['after_proof']['build'] as String).substring(0, 8)} is running.',
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'The original identity and claim were verified.',
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Next: open Test bench to inspect the credential reservation.',
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        if (phase == 'review_required')
          const Text(
            'A previous update is unresolved. Review its saved evidence before any further update.',
          ),
        if (phase == 'interrupted_after_write')
          const Text(
            'Update needs review. Keep the saved attempt; do not retry the write automatically.',
          ),
        if (detail != null) ...[
          const SizedBox(height: 12),
          SelectableText(detail!),
        ],
        if (saved != null) ...[
          const SizedBox(height: 12),
          ExpansionTile(
            title: const Text('Update report'),
            children: [
              ListTile(
                title: Text('Attempt ${saved['id']}'),
                subtitle: Text('Status: ${saved['phase']}'),
              ),
              ListTile(
                title: const Text('Before firmware'),
                subtitle: Text(saved['before_source'] as String),
              ),
              ListTile(
                title: const Text('After firmware'),
                subtitle: Text(saved['after_source'] as String),
              ),
              TextField(
                controller: folder,
                decoration: const InputDecoration(
                  labelText: 'Export folder',
                  hintText: 'Absolute path to an existing folder',
                ),
              ),
              OutlinedButton(
                onPressed: c.busy
                    ? null
                    : () => _action(() async {
                        final path = await session!.export(folder.text.trim());
                        if (mounted) setState(() => exported = path);
                      }),
                child: const Text('Export update report'),
              ),
              if (exported != null) SelectableText('Exported to $exported'),
            ],
          ),
        ],
        if (session != null) ...[
          const SizedBox(height: 12),
          ExpansionTile(
            title: const Text('Update tester guide'),
            children: [
              for (final step in session!.guide['steps'] as List)
                ListTile(
                  title: Text('${step['number']}. ${step['action']}'),
                  subtitle: Text(step['expected'] as String),
                ),
            ],
          ),
        ],
      ],
    );
  }
}
