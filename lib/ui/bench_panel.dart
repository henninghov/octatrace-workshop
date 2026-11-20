import 'dart:convert';

import 'package:flutter/material.dart';

import '../domain/workshop_controller.dart';

class BenchPanel extends StatefulWidget {
  const BenchPanel({super.key, required this.controller});
  final WorkshopController controller;
  @override
  State<BenchPanel> createState() => _BenchPanelState();
}

class _BenchPanelState extends State<BenchPanel> {
  final label = TextEditingController(), folder = TextEditingController();
  String? deviceId, exported;
  bool unreadable = false;
  @override
  void dispose() {
    label.dispose();
    folder.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.controller, s = c.bench;
    if (s == null) {
      return TextButton(
        onPressed: c.busy ? null : c.enterBench,
        child: const Text('Open test bench'),
      );
    }
    final registry = c.registry!;
    final devices = registry.devices
        .where((d) => d.state == 'provisioned')
        .toList();
    final serials = <String, String>{
      for (final row in s.sharedHistory)
        for (final p in row['header']['participants'])
          p['device_id']: p['device_id'],
      for (final r in s.history) r['device']['id']: r['device']['serial'],
      for (final d in devices) d.id: d.serial,
    };
    final requested = s.active
        ? (s.report?['device']['id'] ?? s.pending?['device']['id'])
        : deviceId;
    final selectedId = serials.containsKey(requested)
        ? requested
        : devices.firstOrNull?.id ?? serials.keys.firstOrNull;
    final selected = devices.where((d) => d.id == selectedId).firstOrNull;
    final article = registry.articles
        .where((a) => a.id == selected?.revisionId)
        .firstOrNull;
    final build = s.definition.builds
        .where((b) => b.role == article?.role)
        .firstOrNull;
    final guide = s.definition.guide, report = s.report;
    final viewing = report != null && report['device']['id'] == selectedId;
    final steps = guide['steps'] as List;
    final next = s.active && report != null ? s.next : 0;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Test bench', style: Theme.of(context).textTheme.headlineSmall),
        Text('${guide['title']} · Local definition v${guide['revision']}'),
        const SizedBox(height: 16),
        if (devices.isEmpty)
          const Text('A provisioned registry device is required.'),
        if (selectedId != null)
          DropdownButton<String>(
            value: selectedId,
            isExpanded: true,
            items: [
              for (final entry in serials.entries)
                DropdownMenuItem(value: entry.key, child: Text(entry.value)),
            ],
            onChanged: c.busy || s.active
                ? null
                : (value) => setState(() {
                    deviceId = value;
                    exported = null;
                  }),
          ),
        if (selected != null)
          SelectableText(
            '${selected.id} · ${article?.role ?? 'Unknown role'} · ${selected.ownerId == null ? 'Unclaimed' : 'Claimed'}',
          ),
        if (build != null)
          SelectableText(
            'Firmware ${build.version}\nSource ${build.source}\nExpected image ${build.artifact}',
          ),
        ExpansionTile(
          title: const Text('Prerequisites and tester guide'),
          children: [
            for (final line in guide['prerequisites'])
              ListTile(title: Text(line)),
            for (final step in steps)
              ListTile(
                title: Text(
                  "${step['number']}. ${step['actor']} · ${step['action']}",
                ),
                subtitle: Text(
                  "Expected: ${step['expected']}\nEvidence: ${step['evidence'].join(' · ')}",
                ),
              ),
          ],
        ),
        if (!s.active && selected != null && article != null && build != null)
          FilledButton(
            onPressed: c.busy
                ? null
                : () {
                    label.clear();
                    setState(() {
                      exported = null;
                      unreadable = false;
                      deviceId = selected.id;
                    });
                    c.benchAction(
                      (session) => session.start(selected, article),
                    );
                  },
            child: Text(
              s.history.any((r) => r['device']['id'] == selected.id)
                  ? 'Run again · new attempt'
                  : 'Start guided test',
            ),
          ),
        if (s.pending != null)
          OutlinedButton(
            onPressed: c.busy
                ? null
                : () => c.benchAction((s) => s.retrySave()),
            child: const Text('Retry local save'),
          ),
        if (viewing) ...[
          const Divider(),
          SelectableText(
            "Attempt ${report['id']} · ${s.active && report['outcome'] == 'Incomplete' ? 'In progress' : report['outcome']} · ${s.verifiedGenerations[report['id']] == report['generation'] ? 'Server verified' : 'Local only'}",
          ),
          LayoutBuilder(
            builder: (context, constraints) {
              final sequence = Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  for (final step in report['steps'])
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 5),
                      child: Text(
                        "${step['number']}. ${const ['Select device', 'Save attempt', 'Connect USB', 'Read identity', 'Compare label', 'Reopen report', 'Export report'][step['number'] - 1]}\n${step['actor']} · ${step['status']}",
                      ),
                    ),
                ],
              );
              final action = Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (report['steps'][3]['status'] == 'Passed')
                        SelectableText(
                          "USB readback · ${report['steps'][3]['evidence']['frame']['serial']}",
                        ),
                      if (report['steps'][3]['evidence'] case {
                        'error': final String error,
                      })
                        SelectableText(error),
                      if (report['steps'][4]['evidence'] case {
                        'observation': final String observed,
                      })
                        SelectableText('Tester observation · $observed'),
                      if (next > 0) ...[
                        const SizedBox(height: 12),
                        Text(
                          "Step $next · ${steps[next - 1]['action']}",
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        Text("Expected: ${steps[next - 1]['expected']}"),
                      ],
                      if (next == 3 && selected != null && article != null)
                        FilledButton(
                          onPressed: c.busy || s.pending != null
                              ? null
                              : () => c.benchAction(
                                  (s) => s.connected(selected, article),
                                ),
                          child: const Text('USB connected · read identity'),
                        ),
                      if (next == 4 && selected != null && article != null)
                        FilledButton(
                          onPressed: c.busy || s.pending != null
                              ? null
                              : () => c.benchAction(
                                  (session) =>
                                      session.readDevice(selected, article),
                                ),
                          child: const Text('Read identity'),
                        ),
                      if (next == 5) ...[
                        TextField(
                          controller: label,
                          maxLength: 256,
                          decoration: InputDecoration(
                            labelText: unreadable
                                ? 'Reason label is unavailable'
                                : 'Observed label serial',
                          ),
                        ),
                        CheckboxListTile(
                          value: unreadable,
                          onChanged: c.busy
                              ? null
                              : (v) => setState(() => unreadable = v!),
                          title: const Text('Label unavailable'),
                        ),
                        FilledButton(
                          onPressed: c.busy || s.pending != null
                              ? null
                              : () => c.benchAction(
                                  (s) => s.observe(
                                    label.text,
                                    unavailable: unreadable,
                                  ),
                                ),
                          child: const Text('Save observation'),
                        ),
                      ],
                      if (next == 6)
                        FilledButton(
                          onPressed: c.busy
                              ? null
                              : () => c.benchAction((s) => s.verifyReopen()),
                          child: const Text('Verify reopened report'),
                        ),
                      if (next == 7 || !s.active) ...[
                        TextField(
                          controller: folder,
                          decoration: const InputDecoration(
                            labelText: 'Export folder',
                            hintText: 'Absolute path to an existing folder',
                          ),
                        ),
                        OutlinedButton(
                          onPressed: c.busy || s.pending != null
                              ? null
                              : () => c.benchAction((s) async {
                                  final path = await s.export(
                                    folder.text.trim(),
                                  );
                                  if (mounted) setState(() => exported = path);
                                }),
                          child: const Text('Export report'),
                        ),
                      ],
                    ],
                  ),
                ),
              );
              if (constraints.maxWidth < 560) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [sequence, action],
                );
              }
              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(width: 180, child: sequence),
                  Expanded(child: action),
                ],
              );
            },
          ),
          if (s.sync != null &&
              !s.active &&
              s.verifiedGenerations[report['id']] != report['generation'])
            OutlinedButton.icon(
              icon: const Icon(Icons.cloud_upload_outlined),
              label: const Text('Sync saved attempt'),
              onPressed: c.busy || s.pending != null
                  ? null
                  : () => c.benchAction((s) => s.syncSelected()),
            ),
          if (exported != null) SelectableText('Exported to $exported'),
          ExpansionTile(
            title: const Text('Report details'),
            children: [
              SelectableText(
                const JsonEncoder.withIndent('  ').convert(report),
              ),
            ],
          ),
        ],
        if (s.active)
          TextButton(
            onPressed: c.cancelBench,
            child: const Text('Cancel attempt'),
          ),
        const Divider(),
        Text('Device history', style: Theme.of(context).textTheme.titleMedium),
        if (s.sync != null)
          TextButton(
            onPressed: c.busy || s.active
                ? null
                : () => c.benchAction((s) => s.loadSharedHistory()),
            child: const Text('Load shared history'),
          ),
        for (final remote in s.sharedHistory.where(
          (row) =>
              (row['header']['participants'] as List).any(
                (p) => p['device_id'] == selectedId,
              ) &&
              !s.history.any((r) => r['id'] == row['header']['id']),
        ))
          ExpansionTile(
            title: Text(
              "${remote['result']['outcome']} · ${remote['header']['started_at']}",
            ),
            subtitle: Text("Shared attempt · ${remote['header']['id']}"),
            children: [
              for (final step in remote['result']['steps'])
                ListTile(
                  title: Text(
                    "Step ${step['number']} · ${step['actor']} · ${step['status']}",
                  ),
                  subtitle: step.containsKey('evidence')
                      ? SelectableText(jsonEncode(step['evidence']))
                      : null,
                ),
              for (final artifact in remote['result']['artifacts']) ...[
                TextButton(
                  onPressed: c.busy
                      ? null
                      : () => c.benchAction(
                          (s) => s.readSharedArtifact(remote, artifact),
                        ),
                  child: Text(
                    "Read step ${artifact['step']} attachment · ${artifact['bytes']} bytes",
                  ),
                ),
                if (s.sharedArtifacts[s.attachmentKey(remote, artifact)]
                    case final text?)
                  SelectableText(text),
              ],
            ],
          ),
        for (final r in s.history.where((r) => r['device']['id'] == selectedId))
          ListTile(
            title: Text(
              "${s.active && r['id'] == report?['id'] && r['outcome'] == 'Incomplete' ? 'In progress' : r['outcome']} · ${r['started_at']}",
            ),
            subtitle: Text("${r['id']}"),
            enabled: !c.busy && !s.active,
            onTap: () {
              setState(() => exported = null);
              c.benchAction((s) => s.open(r['id']));
            },
          ),
      ],
    );
  }
}
