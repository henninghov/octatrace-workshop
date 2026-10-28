import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../domain/registry.dart';
import '../domain/workshop_controller.dart';
import 'article_editor.dart';
import 'copyable_text.dart';
import 'provisioning_panel.dart';

const orange = Color(0xfff46628);
const charcoal = Color(0xff252525);
const paper = Color(0xfff7f5f1);
const ink = Color(0xff111920);

class WorkshopApp extends StatefulWidget {
  const WorkshopApp({super.key, required this.controller, this.links});
  final Stream<Uri>? links;
  final WorkshopController? controller;
  @override
  State<WorkshopApp> createState() => _WorkshopAppState();
}

class _WorkshopAppState extends State<WorkshopApp> {
  bool dark = false;
  StreamSubscription<Uri>? _links;
  @override
  void initState() {
    super.initState();
    _links = widget.links?.listen(
      (uri) => widget.controller?.acceptLink(uri),
      onError: (Object _) => widget.controller?.linkDeliveryFailed(),
    );
  }

  @override
  void dispose() {
    _links?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Octatrace Workshop',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      useMaterial3: true,
      fontFamily: 'Excon',
      brightness: dark ? Brightness.dark : Brightness.light,
      colorScheme:
          ColorScheme.fromSeed(
            seedColor: orange,
            brightness: dark ? Brightness.dark : Brightness.light,
          ).copyWith(
            primary: dark ? orange : ink,
            onPrimary: dark ? ink : Colors.white,
            surface: dark ? const Color(0xff1c2022) : Colors.white,
            onSurface: dark ? paper : ink,
            onSurfaceVariant: dark
                ? const Color(0xffb0b5ad)
                : const Color(0xff656864),
            outline: dark ? const Color(0xff4d5552) : const Color(0xffdededb),
          ),
      cardTheme: CardThemeData(
        color: dark ? const Color(0xff252b2c) : paper,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(
            color: dark ? const Color(0xff4d5552) : const Color(0xffdededb),
          ),
        ),
      ),
      scaffoldBackgroundColor: dark ? const Color(0xff1c2022) : Colors.white,
      inputDecorationTheme: const InputDecorationTheme(
        border: OutlineInputBorder(),
        isDense: true,
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: orange,
          foregroundColor: ink,
          padding: const EdgeInsets.all(18),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      textTheme: const TextTheme(
        bodyMedium: TextStyle(fontSize: 13),
        titleLarge: TextStyle(fontSize: 26, fontWeight: FontWeight.w500),
      ),
    ),
    home: WorkshopShell(
      controller: widget.controller,
      dark: dark,
      toggleTheme: () => setState(() => dark = !dark),
    ),
  );
}

class WorkshopShell extends StatefulWidget {
  const WorkshopShell({
    super.key,
    required this.controller,
    required this.dark,
    required this.toggleTheme,
  });
  final WorkshopController? controller;
  final bool dark;
  final VoidCallback toggleTheme;
  @override
  State<WorkshopShell> createState() => _WorkshopShellState();
}

class _WorkshopShellState extends State<WorkshopShell> {
  final email = TextEditingController();
  final port = TextEditingController(), sourceBuild = TextEditingController();
  String page = 'Devices', serialClass = 'D';
  String? revisionId, deviceId;
  bool creatingDevice = true;
  WorkshopController? get c => widget.controller;
  @override
  void initState() {
    super.initState();
    c?.addListener(changed);
  }

  void changed() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    c?.removeListener(changed);
    c?.dispose();
    for (final f in [email, port, sourceBuild]) {
      f.dispose();
    }
    super.dispose();
  }

  Widget gap([double n = 16]) => SizedBox(height: n);
  Widget logo([double width = 132]) => SvgPicture.asset(
    'assets/branding/wordmark.svg',
    width: width,
    height: width * 235.368 / 1040,
    semanticsLabel: 'Octatrace',
  );
  Widget heading(String eyebrow, String title, String subtitle) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        eyebrow.toUpperCase(),
        style: const TextStyle(color: orange, fontSize: 11, letterSpacing: 1),
      ),
      gap(8),
      Text(title, style: Theme.of(context).textTheme.titleLarge),
      gap(8),
      Text(subtitle),
      gap(28),
    ],
  );
  Widget notice(String text, {bool warning = false}) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: warning ? const Color(0xffffefe3) : const Color(0xffeaf2f8),
      borderRadius: BorderRadius.circular(8),
    ),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(
          warning ? Icons.warning_amber_rounded : Icons.info_outline,
          size: 18,
          color: ink,
        ),
        const SizedBox(width: 10),
        Expanded(
          child: CopyableText(
            label: 'Message',
            value: text,
            showLabel: false,
            style: const TextStyle(color: ink),
          ),
        ),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Column(
      children: [
        Container(
          height: 40,
          color: widget.dark ? charcoal : paper,
          padding: const EdgeInsets.symmetric(horizontal: 20),
          child: Row(
            children: [
              const Text('Octatrace Workshop'),
              const Spacer(),
              TextButton.icon(
                onPressed: widget.toggleTheme,
                icon: Icon(
                  widget.dark
                      ? Icons.light_mode_outlined
                      : Icons.dark_mode_outlined,
                  size: 16,
                ),
                label: Text(widget.dark ? 'Light mode' : 'Dark mode'),
              ),
            ],
          ),
        ),
        if (c?.access != Access.ready)
          Expanded(child: login())
        else
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SizedBox(width: 190, child: sidebar()),
                Expanded(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.all(28),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(child: Text('Workspace / $page')),
                            IconButton(
                              tooltip: 'Refresh registry',
                              onPressed: c!.busy ? null : c!.refresh,
                              icon: const Icon(Icons.refresh, size: 19),
                            ),
                          ],
                        ),
                        gap(20),
                        if (c!.message != null) ...[
                          notice(c!.message!, warning: true),
                          gap(),
                        ],
                        if (c!.busy) ...[
                          const LinearProgressIndicator(),
                          gap(),
                        ],
                        switch (page) {
                          'Articles' => articles(),
                          'Provisioning' => provisioning(),
                          'Setup history' => history(),
                          _ => devices(),
                        },
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
      ],
    ),
  );

  Widget login() => LayoutBuilder(
    builder: (context, constraints) {
      final form = Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                heading(
                  'Operator access',
                  'Welcome to the bench.',
                  'Sign in with your Octatrace account.',
                ),
                if (c == null) ...[
                  notice(
                    'Configure the Supabase project and publishable key. See config/development.example.json.',
                  ),
                  gap(),
                ],
                if (c?.message != null) ...[
                  notice(
                    c!.message!,
                    warning: c!.access != Access.awaitingLink,
                  ),
                  gap(),
                ],
                TextField(
                  controller: email,
                  enabled:
                      c != null && !c!.busy && c!.access != Access.awaitingLink,
                  keyboardType: TextInputType.emailAddress,
                  decoration: const InputDecoration(labelText: 'Email address'),
                  onSubmitted: (_) => submitLogin(),
                ),
                gap(24),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton(
                    onPressed: c != null && !c!.busy ? submitLogin : null,
                    child: Text(
                      c?.busy == true
                          ? (c?.access == Access.sendingLink
                                ? 'Sending link…'
                                : c?.access == Access.signingIn
                                ? 'Signing in…'
                                : 'Signing out…')
                          : c?.access == Access.awaitingLink
                          ? 'Send a new link'
                          : 'Send sign-in link',
                    ),
                  ),
                ),
                if (c?.access == Access.awaitingLink) ...[
                  gap(8),
                  TextButton(
                    onPressed: c!.signOut,
                    child: const Text('Cancel sign-in'),
                  ),
                ],
                gap(20),
                const Text(
                  'A Workshop operator role is required. Your operator identity is attached to every preparation record.',
                ),
              ],
            ),
          ),
        ),
      );
      if (constraints.maxWidth < 900 || constraints.maxHeight < 700) {
        return form;
      }
      return Row(
        children: [
          Expanded(
            flex: 5,
            child: Container(
              color: charcoal,
              padding: const EdgeInsets.all(48),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SvgPicture.asset(
                    'assets/branding/compass.svg',
                    width: 96,
                    height: 96,
                    semanticsLabel: 'Octatrace compass',
                  ),
                  gap(36),
                  logo(220),
                  gap(16),
                  const Text(
                    'WORKSHOP',
                    style: TextStyle(
                      color: orange,
                      letterSpacing: 3,
                      fontSize: 11,
                    ),
                  ),
                  gap(72),
                  const Text(
                    'Every device.',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 34,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const Text(
                    'Ready for the field.',
                    style: TextStyle(
                      color: orange,
                      fontSize: 34,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  gap(20),
                  const Text(
                    'Set up, test and verify your Octatrace devices from one place.',
                    style: TextStyle(color: Colors.white70, height: 1.7),
                  ),
                  const Spacer(),
                  const Text(
                    'Device setup & diagnostics\nLocal macOS application',
                    style: TextStyle(color: Colors.white70, height: 1.7),
                  ),
                ],
              ),
            ),
          ),
          Expanded(flex: 5, child: form),
        ],
      );
    },
  );
  void submitLogin() {
    if (c?.busy != false) return;
    c!.requestLink(email.text);
  }

  Widget sidebar() => Container(
    color: charcoal,
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 28),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        logo(),
        gap(10),
        const Text(
          'WORKSHOP',
          style: TextStyle(color: orange, letterSpacing: 2, fontSize: 11),
        ),
        gap(32),
        for (final entry in {
          'Devices': Icons.sensors,
          'Articles': Icons.inventory_2_outlined,
          'Provisioning': Icons.usb,
          'Setup history': Icons.history,
        }.entries)
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: TextButton.icon(
              style: TextButton.styleFrom(
                alignment: Alignment.centerLeft,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                foregroundColor: Colors.white70,
                backgroundColor: page == entry.key
                    ? const Color(0xff3a3936)
                    : Colors.transparent,
                minimumSize: const Size(double.infinity, 46),
                padding: const EdgeInsets.symmetric(horizontal: 10),
              ),
              onPressed: c!.busy
                  ? null
                  : () => setState(() => page = entry.key),
              icon: Icon(
                entry.value,
                color: page == entry.key ? orange : Colors.white70,
                size: 18,
              ),
              label: Text(entry.key),
            ),
          ),
        const Spacer(),
        const Text(
          'Provisioned by us.\nClaimed by the user.',
          style: TextStyle(color: Colors.white70, height: 1.7),
        ),
        gap(20),
        TextButton.icon(
          onPressed: () {
            deviceId = null;
            revisionId = null;
            c!.signOut();
          },
          icon: const Icon(Icons.logout, color: Colors.white70, size: 17),
          label: const Text(
            'Sign out',
            style: TextStyle(color: Colors.white70),
          ),
        ),
      ],
    ),
  );

  Widget articles() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      heading(
        'Articles / Manufacturing definitions',
        'Build from a known revision.',
        'Parts and case versions stay with the devices built from them.',
      ),
      FilledButton.icon(
        onPressed: c!.busy ? null : () => editArticle(),
        icon: const Icon(Icons.add, size: 18),
        label: const Text('New article'),
      ),
      gap(),
      if (c!.registry!.articles.isEmpty)
        notice(
          'Create the first article and parts list before reserving a device.',
        ),
      for (final a in c!.registry!.articles)
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        '${a.code} · ${a.name}',
                        style: const TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                    TextButton(
                      onPressed: c!.busy ? null : () => editArticle(a),
                      child: const Text('New revision'),
                    ),
                  ],
                ),
                gap(6),
                Text(
                  '${a.role.toUpperCase()} · Revision ${a.revision} · Case ${a.caseVersion}',
                ),
                gap(),
                for (final p in a.parts)
                  Text(
                    '${p['quantity']} × ${p['part_number']} — ${p['description']}',
                  ),
              ],
            ),
          ),
        ),
    ],
  );
  Future<void> editArticle([ArticleRevision? existing]) async {
    final draft = await showDialog<ArticleDraft>(
      context: context,
      builder: (_) => ArticleEditor(
        existing: existing,
        availableParts: c!.registry!.articles.expand((a) => a.parts).toList(),
      ),
    );
    if (draft == null || !mounted) return;
    await c!.action(
      () => existing == null
          ? c!.gateway.createArticle(
              code: draft.code,
              name: draft.name,
              role: draft.role,
              caseVersion: draft.caseVersion,
              parts: draft.parts,
            )
          : c!.gateway.addRevision(
              articleId: existing.articleId,
              caseVersion: draft.caseVersion,
              parts: draft.parts,
            ),
    );
  }

  Future<void> reserveDevice(String revision) async {
    final account = c!.gateway.accountId;
    final deviceClass = serialClass;
    final reservedId = await c!.reserve(revision, deviceClass);
    if (!mounted || c!.gateway.accountId != account) return;
    final created = c!.registry?.devices
        .where(
          (d) =>
              d.id == reservedId &&
              d.revisionId == revision &&
              d.serial.startsWith(deviceClass),
        )
        .singleOrNull;
    if (created != null) {
      setState(() {
        creatingDevice = false;
        deviceId = created.id;
      });
    }
  }

  Widget devices() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      heading(
        'Device registry',
        'Every device starts here.',
        'Permanent identity, exact build revision and preparation history.',
      ),
      FilledButton.icon(
        onPressed: c!.busy
            ? null
            : () => setState(() {
                deviceId = null;
                revisionId = null;
                serialClass = 'D';
                creatingDevice = true;
                page = 'Provisioning';
              }),
        icon: const Icon(Icons.add, size: 18),
        label: const Text('New device'),
      ),
      gap(),
      if (c!.registry!.devices.isEmpty)
        notice(
          'No devices registered yet. Start with an article and reserve a device identity.',
        ),
      for (final d in c!.registry!.devices) deviceCard(d),
    ],
  );

  Widget deviceCard(DeviceRecord device) {
    final article = c!.registry!.articles
        .where((a) => a.id == device.revisionId)
        .firstOrNull;
    void open() => setState(() {
      creatingDevice = false;
      deviceId = device.id;
      revisionId = device.revisionId;
      page = 'Provisioning';
    });
    return Card(
      key: ValueKey('device-${device.id}'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.sensors),
              title: Text(article?.role.toUpperCase() ?? 'Unknown device type'),
              subtitle: Text(
                article == null
                    ? 'Article revision unavailable'
                    : '${article.code} · Revision ${article.revision}',
              ),
              onTap: c!.busy ? null : open,
              trailing: IconButton(
                tooltip: 'Open device',
                onPressed: c!.busy ? null : open,
                icon: const Icon(Icons.chevron_right),
              ),
            ),
            LayoutBuilder(
              builder: (context, constraints) {
                final fields = [
                  CopyableText(label: 'Serial', value: device.serial),
                  CopyableText(label: 'UUID', value: device.id),
                  CopyableText(label: 'Status', value: deviceStatus(device)),
                ];
                if (constraints.maxWidth < 720) return Column(children: fields);
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: fields[0]),
                    const SizedBox(width: 20),
                    Expanded(flex: 2, child: fields[1]),
                    const SizedBox(width: 20),
                    Expanded(child: fields[2]),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  String deviceStatus(DeviceRecord device) =>
      '${device.state} · ${device.ownerId == null ? 'Unclaimed' : 'Claimed'}';

  Widget provisioning() {
    final revisions = c!.registry!.articles;
    final selected = creatingDevice
        ? null
        : c!.registry!.devices.where((d) => d.id == deviceId).firstOrNull;
    final article = revisions
        .where((a) => a.id == (selected?.revisionId ?? revisionId))
        .firstOrNull;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        heading(
          'Single-device provisioning',
          'Prepare. Verify. Keep the history.',
          'Devices leave Workshop provisioned and unclaimed.',
        ),
        SegmentedButton<bool>(
          segments: const [
            ButtonSegment(
              value: true,
              label: Text('New device'),
              icon: Icon(Icons.add),
            ),
            ButtonSegment(
              value: false,
              label: Text('Existing device'),
              icon: Icon(Icons.sensors),
            ),
          ],
          selected: {creatingDevice},
          onSelectionChanged: c!.busy
              ? null
              : (selection) => setState(() {
                  creatingDevice = selection.single;
                  deviceId = null;
                }),
        ),
        gap(20),
        if (!creatingDevice && c!.registry!.devices.isNotEmpty) ...[
          DropdownButtonFormField<String>(
            key: ValueKey('registry-$deviceId'),
            initialValue: selected?.id,
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Registry device'),
            items: c!.registry!.devices
                .map(
                  (d) => DropdownMenuItem(
                    value: d.id,
                    child: Text(
                      '${d.serial} · ${d.state}',
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                )
                .toList(),
            onChanged: c!.busy
                ? null
                : (value) => setState(() => deviceId = value),
          ),
          gap(20),
        ],
        if (creatingDevice) ...[
          DropdownButtonFormField<String>(
            key: ValueKey(revisionId),
            initialValue: article?.id,
            decoration: const InputDecoration(
              labelText: 'Article and revision',
            ),
            items: revisions
                .map(
                  (a) => DropdownMenuItem(
                    value: a.id,
                    child: Text(
                      '${a.code} · ${a.role.toUpperCase()} · Rev ${a.revision} · Case ${a.caseVersion}',
                    ),
                  ),
                )
                .toList(),
            onChanged: c!.busy ? null : (v) => setState(() => revisionId = v),
          ),
          gap(),
          DropdownButtonFormField<String>(
            initialValue: serialClass,
            decoration: const InputDecoration(labelText: 'Device class'),
            items: const [
              DropdownMenuItem(value: 'D', child: Text('D — Development')),
              DropdownMenuItem(
                value: 'R',
                child: Text('R — Release candidate'),
              ),
              DropdownMenuItem(value: 'O', child: Text('O — Production')),
            ],
            onChanged: c!.busy ? null : (v) => setState(() => serialClass = v!),
          ),
          gap(),
          const Text(
            'One shared sequence · 12 digits · permanent device identity.',
          ),
          gap(24),
          FilledButton(
            onPressed: c!.busy || article == null
                ? null
                : () => reserveDevice(article.id),
            child: const Text('Reserve device identity'),
          ),
          gap(),
          notice(
            'Reserve once to create a UUID and serial. The new record opens here for provisioning.',
          ),
        ] else if (selected == null) ...[
          notice(
            c!.registry!.devices.isEmpty
                ? 'No devices registered. Choose New device to reserve an identity.'
                : 'Select an existing registry device to continue provisioning or update it.',
          ),
        ] else ...[
          CopyableText(
            label: 'Serial',
            value: selected.serial,
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w500),
          ),
          gap(8),
          CopyableText(label: 'UUID', value: selected.id),
          gap(8),
          Text(
            '${article?.role.toUpperCase() ?? 'Unknown device type'} · ${article?.code ?? ''} · Revision ${article?.revision ?? ''}',
          ),
          CopyableText(label: 'Status', value: deviceStatus(selected)),
          gap(20),
          if (c!.provisioningAvailable)
            ProvisioningPanel(
              key: ValueKey(selected.id),
              controller: c!,
              device: selected,
              article: article,
            )
          else ...[
            notice(
              'Current firmware supports USB diagnostics. Permanent identity installation and provisioning completion require the next firmware contract. Registry status: ${selected.state}.',
              warning: true,
            ),
            gap(24),
            TextField(
              controller: port,
              enabled: !c!.busy,
              decoration: const InputDecoration(
                labelText: 'USB port',
                hintText: '/dev/cu.usbmodem…',
              ),
            ),
            gap(),
            TextField(
              controller: sourceBuild,
              enabled: !c!.busy,
              decoration: const InputDecoration(
                labelText: 'Expected full firmware source SHA-256',
              ),
            ),
            gap(20),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                FilledButton(
                  onPressed: c!.busy || article == null
                      ? null
                      : () => c!.verify(
                          selected,
                          article,
                          port.text.trim(),
                          sourceBuild.text.trim(),
                        ),
                  child: const Text('Read identity with shared runner'),
                ),
                OutlinedButton(
                  onPressed: c!.busy || article == null
                      ? null
                      : () => c!.verify(
                          selected,
                          article,
                          port.text.trim(),
                          sourceBuild.text.trim(),
                          command: 'check',
                        ),
                  child: const Text('Run shared USB checks'),
                ),
                if (c!.busy)
                  OutlinedButton(
                    onPressed: c!.cancel,
                    child: const Text('Cancel'),
                  ),
                const OutlinedButton(
                  onPressed: null,
                  child: Text('Install and provision'),
                ),
              ],
            ),
            gap(20),
            if (c!.readback != null && c!.readbackDeviceId == selected.id) ...[
              CopyableText(
                label: 'Message',
                showLabel: false,
                value: c!.readbackSaved
                    ? 'Diagnostic saved · provisioning unchanged'
                    : 'Readback received · record not saved',
              ),
              gap(),
              CopyableText(
                label: 'Diagnostic',
                showLabel: false,
                value: const JsonEncoder.withIndent('  ').convert(c!.readback),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ],
          ],
        ],
      ],
    );
  }

  Widget history() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      heading(
        'Setup history',
        'Every attempt stays with the device.',
        'Server-stamped operator, time and evidence. Diagnostics do not imply provisioning.',
      ),
      if (c!.pendingEvidence > 0) ...[
        notice(
          '${c!.pendingEvidence} local evidence records await upload. Local copies are retained.',
        ),
        gap(),
        OutlinedButton(
          onPressed: c!.busy ? null : c!.syncEvidence,
          child: const Text('Retry evidence upload'),
        ),
        gap(),
      ],
      if (c!.registry!.runs.isEmpty) notice('No preparation records yet.'),
      for (final run in c!.registry!.runs)
        Card(
          child: ExpansionTile(
            title: Text('${run['event_type']} · ${run['recorded_at']}'),
            subtitle: CopyableText(
              label: 'UUID',
              value: run['device_id'] as String,
            ),
            children: [
              Padding(
                padding: const EdgeInsets.all(16),
                child: CopyableText(
                  label: 'Diagnostic',
                  showLabel: false,
                  value: const JsonEncoder.withIndent('  ').convert(run),
                ),
              ),
            ],
          ),
        ),
    ],
  );
}
