import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../domain/factory_controller.dart';
import '../domain/factory_enrollment.dart';
import '../domain/registry.dart';
import '../domain/workshop_controller.dart';
import 'copyable_text.dart';

class FactoryPanel extends StatefulWidget {
  const FactoryPanel({
    super.key,
    required this.workshop,
    required this.device,
    required this.article,
  });
  final WorkshopController workshop;
  final DeviceRecord device;
  final ArticleRevision article;
  @override
  State<FactoryPanel> createState() => _FactoryPanelState();
}

class _FactoryPanelState extends State<FactoryPanel>
    with WidgetsBindingObserver {
  late final FactoryController factory;
  @override
  void initState() {
    super.initState();
    final workshop = widget.workshop;
    final account = workshop.gateway.accountId!;
    factory = FactoryController(
      workshop.gateway as FactoryGateway,
      workshop.journal,
      account: account,
      device: widget.device,
      role: widget.article.role,
      createId: newRequestId,
      isCurrent: () =>
          workshop.access == Access.ready &&
          workshop.gateway.accountId == account &&
          !workshop.busy,
    );
    factory.addListener(changed);
    workshop.addListener(accessChanged);
    WidgetsBinding.instance.addObserver(this);
    unawaited(factory.refresh());
  }

  void changed() {
    if (mounted) setState(() {});
  }

  void accessChanged() {
    final w = widget.workshop;
    if (w.access != Access.ready ||
        w.gateway.accountId != factory.account ||
        w.busy) {
      factory.hide();
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      factory.hide(
        explanation: 'Private QR hidden when Workshop left the foreground.',
      );
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.workshop.removeListener(accessChanged);
    factory.removeListener(changed);
    factory.dispose();
    super.dispose();
  }

  String? get proofId {
    for (final run in widget.workshop.registry?.runs ?? <Json>[]) {
      if (run['device_id'] == widget.device.id &&
          run['operator_user_id'] == factory.account &&
          run['event_type'] == 'provisioned' &&
          factoryUuid(run['id'])) {
        return run['id'] as String;
      }
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final w = widget.workshop, f = factory, proof = proofId;
    final enabled = !w.busy && !f.busy;
    final status = switch (f.status?.state) {
      'ready' => 'Factory credential issued · claim QR ready',
      'pending' => 'Factory enrollment pending',
      'not_enrolled' => 'Factory credential not issued',
      _ => 'Factory status not confirmed',
    };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(height: 40),
        Text(
          'Factory credential and claim QR',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 12),
        Text(status),
        const SizedBox(height: 8),
        const Text(
          'The claim QR is prepared here. The user claims ownership separately in the app.',
        ),
        if (!f.eligible)
          const Padding(
            padding: EdgeInsets.only(top: 8),
            child: Text(
              'Factory issuance is available for verified development LINK and CORE devices.',
            ),
          ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            OutlinedButton(
              onPressed: enabled ? f.refresh : null,
              child: const Text('Refresh claim-code status'),
            ),
            if (f.canIssue)
              FilledButton(
                onPressed: enabled && proof != null
                    ? () => f.issue(proof)
                    : null,
                child: const Text('Issue factory credential and claim code'),
              ),
            if (f.canReveal)
              FilledButton(
                onPressed: enabled ? f.reveal : null,
                child: const Text('Reveal private claim QR'),
              ),
            if (f.busy)
              OutlinedButton(
                onPressed: () => f.hide(
                  explanation: 'View cancelled. Accepted server work may finish; refresh status to recover.',
                ),
                child: const Text('Cancel'),
              ),
          ],
        ),
        if (f.busy) ...[
          const SizedBox(height: 12),
          const LinearProgressIndicator(
            semanticsLabel: 'Checking factory enrollment',
          ),
        ],
        if (f.canIssue && proof == null)
          const Padding(
            padding: EdgeInsets.only(top: 12),
            child: Text(
              'Complete Verify and provision with this account first. A confirmed USB proof is required to issue the credential.',
            ),
          ),
        if (f.message != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Text(f.message!),
          ),
        const SizedBox(height: 16),
        const Text(
          'Private QR reveal requires internet, current operator access and sign-in within the last 15 minutes. Refreshing does not renew sign-in.',
        ),
        TextButton(
          onPressed: w.busy
              ? null
              : () {
                  f.hide();
                  unawaited(w.signOut());
                },
          child: const Text('Sign in again'),
        ),
        if (f.privateQr case final qr?) ...[
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: Text(
                  'Private claim QR · ${widget.article.role.toUpperCase()}',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
              TextButton(
                onPressed: () => f.hide(explanation: 'Private QR hidden.'),
                child: const Text('Hide QR'),
              ),
            ],
          ),
          const Text(
            'Scan this code when adding this device in the app. Keep the private code concealed.',
          ),
          const SizedBox(height: 16),
          Center(
            child: LayoutBuilder(
              builder: (context, constraints) => QrImageView(
                data: qr.text,
                version: 8,
                errorCorrectionLevel: QrErrorCorrectLevel.M,
                size: math.min(320, constraints.maxWidth),
                padding: const EdgeInsets.all(28),
                backgroundColor: Colors.white,
                eyeStyle: const QrEyeStyle(
                  eyeShape: QrEyeShape.square,
                  color: Colors.black,
                ),
                dataModuleStyle: const QrDataModuleStyle(
                  dataModuleShape: QrDataModuleShape.square,
                  color: Colors.black,
                ),
                semanticsLabel: 'Private claim QR for ${widget.device.serial}',
              ),
            ),
          ),
          const SizedBox(height: 8),
          ExpansionTile(
            title: const Text('Raw claim payload'),
            tilePadding: EdgeInsets.zero,
            children: [
              CopyableText(label: 'Private claim payload', value: qr.text),
            ],
          ),
        ],
      ],
    );
  }
}
