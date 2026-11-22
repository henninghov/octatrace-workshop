import 'dart:convert';

import 'package:flutter/material.dart';

import '../domain/bench_definition.dart';
import '../domain/workshop_controller.dart';

class BenchPanel extends StatefulWidget {
  const BenchPanel({super.key, required this.controller});
  final WorkshopController controller;
  @override
  State<BenchPanel> createState() => _BenchPanelState();
}

class _BenchPanelState extends State<BenchPanel> {
  final label = TextEditingController(), folder = TextEditingController();
  final historyKey = GlobalKey();
  String? deviceId, exported;
  bool unreadable = false;
  String logScope = 'Entire attempt', logSource = 'All';
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
    final report = s.report;
    final viewing = report != null && report['device']['id'] == selectedId;
    final guide = viewing
        ? BenchDefinition.fromSnapshot(report['definition_snapshot']).guide
        : s.definition.guide;
    final inspection = guide['key'] == 'c82-credential-inspection-device';
    final steps = guide['steps'] as List;
    final next = s.active && report != null ? s.next : 0;
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final dark = theme.brightness == Brightness.dark;
    final muted = colors.onSurfaceVariant;
    final outline = colors.outline;
    final surface = dark ? const Color(0xff252b2c) : const Color(0xfff7f5f1);
    final accent = const Color(0xfff46628);
    final success = dark ? const Color(0xff9ed8b2) : const Color(0xff24684c);
    final successSurface = dark
        ? const Color(0xff24372d)
        : const Color(0xffedf5ef);
    final names = inspection
        ? const [
            'Select device',
            'Save attempt',
            'Connect USB',
            'Inspect storage',
            'Record observation',
            'Reopen report',
            'Export report',
          ]
        : const [
            'Select device',
            'Save attempt',
            'Connect USB',
            'Read identity',
            'Compare label',
            'Reopen report',
            'Export report',
          ];
    final displayedSteps = viewing
        ? report['steps'] as List
        : [
            for (final step in steps)
              {
                'number': step['number'],
                'actor': step['actor'],
                'status': 'Not run',
              },
          ];
    final currentStep = next > 0 ? steps[next - 1] as Map : null;

    Widget field(String title, Widget child) => Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: TextStyle(color: muted, fontSize: 11)),
        const SizedBox(height: 6),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: surface,
            border: Border.all(color: outline),
            borderRadius: BorderRadius.circular(8),
          ),
          child: DropdownButtonHideUnderline(child: child),
        ),
      ],
    );

    final deviceField = selectedId == null
        ? Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: surface,
              border: Border.all(color: outline),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Text('No device available'),
          )
        : field(
            'Device',
            DropdownButton<String>(
              key: const ValueKey('bench-device-selector'),
              value: selectedId,
              isExpanded: true,
              disabledHint: Text(
                serials[selectedId]!,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: colors.onSurface),
              ),
              items: [
                for (final entry in serials.entries)
                  DropdownMenuItem(
                    value: entry.key,
                    child: Text(entry.value, overflow: TextOverflow.ellipsis),
                  ),
              ],
              onChanged: c.busy || s.active
                  ? null
                  : (value) => setState(() {
                      deviceId = value;
                      exported = null;
                    }),
            ),
          );
    final sequenceField = s.inspectionDefinition == null
        ? field(
            'Test sequence',
            DropdownButton<String>(
              value: s.definition.guide['title'] as String,
              isExpanded: true,
              disabledHint: Text(
                s.definition.guide['title'],
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: colors.onSurface),
              ),
              items: [
                DropdownMenuItem(
                  value: s.definition.guide['title'] as String,
                  child: Text(
                    s.definition.guide['title'],
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
              onChanged: null,
            ),
          )
        : field(
            'Test sequence',
            DropdownButton<BenchDefinition>(
              value: s.definition,
              isExpanded: true,
              disabledHint: Text(
                s.definition.guide['title'],
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: colors.onSurface),
              ),
              items: [
                for (final definition in [
                  s.identityDefinition,
                  s.inspectionDefinition!,
                ])
                  DropdownMenuItem(
                    value: definition,
                    child: Text(
                      definition.guide['title'],
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
              ],
              onChanged: c.busy || s.active || s.pending != null
                  ? null
                  : (value) {
                      if (value != null) {
                        c.benchAction(
                          (session) async => session.selectDefinition(value),
                        );
                      }
                    },
            ),
          );

    final timeline = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final step in displayedSteps)
          Builder(
            builder: (context) {
              final number = step['number'] as int;
              final status = step['status'] as String;
              final passed = status == 'Passed';
              final current = s.active && number == next;
              final dot = passed
                  ? successSurface
                  : current
                  ? accent
                  : surface;
              return IntrinsicHeight(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SizedBox(
                      width: 28,
                      child: Column(
                        children: [
                          Container(
                            width: 28,
                            height: 28,
                            decoration: BoxDecoration(
                              color: dot,
                              shape: BoxShape.circle,
                            ),
                            alignment: Alignment.center,
                            child: passed
                                ? Icon(Icons.check, size: 16, color: success)
                                : Text(
                                    '$number',
                                    style: TextStyle(
                                      fontSize: 11,
                                      color: current
                                          ? const Color(0xff111920)
                                          : muted,
                                    ),
                                  ),
                          ),
                          if (number != displayedSteps.length)
                            Expanded(
                              child: Container(width: 1, color: outline),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Padding(
                        padding: const EdgeInsets.only(bottom: 20),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              names[number - 1],
                              style: const TextStyle(
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 3),
                            Text(
                              current ? 'Current step' : status,
                              style: TextStyle(color: muted, fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
      ],
    );

    final action = Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: surface,
        border: Border.all(color: outline),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  currentStep == null
                      ? (viewing ? 'ATTEMPT RESULT' : 'READY TO BEGIN')
                      : 'STEP $next OF ${steps.length}',
                  style: TextStyle(color: muted, fontSize: 11),
                ),
              ),
              if (currentStep != null)
                Text(
                  currentStep['actor'] == 'tester'
                      ? 'Your action'
                      : 'Automatic check',
                  style: TextStyle(
                    color: currentStep['actor'] == 'tester' ? accent : success,
                    fontSize: 11,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            currentStep != null
                ? currentStep['action'] as String
                : viewing
                ? '${report['outcome']}'
                : 'Start a guided test.',
            style: theme.textTheme.titleLarge,
          ),
          const SizedBox(height: 10),
          if (!viewing)
            Text(
              'Choose a device and test sequence. Each attempt is saved locally before USB discovery.',
              style: TextStyle(color: muted, height: 1.6),
            ),
          if (selected == null)
            Text(
              'A provisioned registry device is required.',
              style: TextStyle(color: muted),
            ),
          if (selected != null && (article == null || build == null))
            Text(
              'This device has no matching article, role or compatible build. Choose a supported device to begin.',
              style: TextStyle(color: muted, height: 1.6),
            ),
          if (viewing && report['steps'][3]['status'] == 'Passed')
            SelectableText(
              inspection
                  ? "Storage · ${report['steps'][3]['evidence']['frame']['state']} · SHA-256 ${report['steps'][3]['evidence']['frame']['sha256']}"
                  : "USB readback · ${report['steps'][3]['evidence']['frame']['serial']}",
            ),
          if (viewing) ...[
            if (report['steps'][3]['evidence'] case {
              'error': final String error,
            })
              SelectableText(error),
            if (report['steps'][4]['evidence'] case {
              'observation': final String observed,
            })
              SelectableText('Tester observation · $observed'),
          ],
          if (currentStep != null) ...[
            const SizedBox(height: 16),
            Divider(color: outline),
            const SizedBox(height: 8),
            Text(
              'Expected result',
              style: TextStyle(color: muted, fontSize: 11),
            ),
            const SizedBox(height: 6),
            Text(
              currentStep['expected'] as String,
              style: const TextStyle(height: 1.6),
            ),
          ],
          const SizedBox(height: 16),
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
                s.history.any(
                      (r) =>
                          r['device']['id'] == selected.id &&
                          r['definition_key'] == s.definition.guide['key'],
                    )
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
          if (next == 3 && selected != null && article != null)
            FilledButton(
              onPressed: c.busy || s.pending != null
                  ? null
                  : () => c.benchAction((s) => s.connected(selected, article)),
              child: Text(
                inspection
                    ? 'USB connected · inspect storage'
                    : 'USB connected · read identity',
              ),
            ),
          if (next == 4 && selected != null && article != null)
            FilledButton(
              onPressed: c.busy || s.pending != null
                  ? null
                  : () => c.benchAction(
                      (session) => session.readDevice(selected, article),
                    ),
              child: Text(inspection ? 'Inspect storage' : 'Read identity'),
            ),
          if (next == 5) ...[
            TextField(
              controller: label,
              maxLength: 256,
              decoration: InputDecoration(
                labelText: unreadable
                    ? inspection
                          ? 'Reason observation is unavailable'
                          : 'Reason label is unavailable'
                    : inspection
                    ? 'Observed storage classification'
                    : 'Observed label serial',
              ),
            ),
            Material(
              type: MaterialType.transparency,
              child: CheckboxListTile(
                value: unreadable,
                onChanged: c.busy
                    ? null
                    : (v) => setState(() => unreadable = v!),
                title: Text(
                  inspection ? 'Observation unavailable' : 'Label unavailable',
                ),
              ),
            ),
            FilledButton(
              onPressed: c.busy || s.pending != null
                  ? null
                  : () => c.benchAction(
                      (s) => s.observe(label.text, unavailable: unreadable),
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
          if (viewing && (next == 7 || !s.active)) ...[
            const SizedBox(height: 12),
            TextField(
              controller: folder,
              decoration: const InputDecoration(
                labelText: 'Export folder',
                hintText: 'Absolute path to an existing folder',
              ),
            ),
            const SizedBox(height: 8),
            OutlinedButton(
              onPressed: c.busy || s.pending != null
                  ? null
                  : () => c.benchAction((s) async {
                      final path = await s.export(folder.text.trim());
                      if (mounted) setState(() => exported = path);
                    }),
              child: const Text('Export report'),
            ),
          ],
        ],
      ),
    );

    final loggedSteps = viewing
        ? (report['steps'] as List).where((step) {
            if (!step.containsKey('at')) return false;
            if (logScope == 'Current step' && step['number'] != next) {
              return false;
            }
            if (logSource != 'All' &&
                step['actor'] != logSource.toLowerCase()) {
              return false;
            }
            return true;
          }).toList()
        : <dynamic>[];
    final evidence = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 22),
        Wrap(
          alignment: WrapAlignment.spaceBetween,
          crossAxisAlignment: WrapCrossAlignment.center,
          spacing: 16,
          runSpacing: 8,
          children: [
            Text('Recorded logs', style: theme.textTheme.titleMedium),
            Wrap(
              crossAxisAlignment: WrapCrossAlignment.center,
              spacing: 6,
              children: [
                Text('Show', style: TextStyle(color: muted, fontSize: 11)),
                DropdownButton<String>(
                  key: const ValueKey('bench-log-scope'),
                  value: logScope,
                  items: const [
                    DropdownMenuItem(
                      value: 'Entire attempt',
                      child: Text('Entire attempt'),
                    ),
                    DropdownMenuItem(
                      value: 'Current step',
                      child: Text('Current step'),
                    ),
                  ],
                  onChanged: (value) => setState(() => logScope = value!),
                ),
                Text('Source', style: TextStyle(color: muted, fontSize: 11)),
                DropdownButton<String>(
                  key: const ValueKey('bench-log-source'),
                  value: logSource,
                  items: const [
                    DropdownMenuItem(value: 'All', child: Text('All')),
                    DropdownMenuItem(value: 'Tester', child: Text('Tester')),
                    DropdownMenuItem(value: 'Runner', child: Text('Runner')),
                  ],
                  onChanged: (value) => setState(() => logSource = value!),
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: 8),
        Container(
          width: double.infinity,
          decoration: BoxDecoration(
            border: Border.all(color: outline),
            borderRadius: BorderRadius.circular(8),
          ),
          child: loggedSteps.isEmpty
              ? Padding(
                  padding: const EdgeInsets.all(14),
                  child: Text(
                    'No recorded steps for this selection.',
                    style: TextStyle(color: muted),
                  ),
                )
              : Column(
                  children: [
                    for (final step in loggedSteps)
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 10,
                        ),
                        decoration: BoxDecoration(
                          border: Border(bottom: BorderSide(color: outline)),
                        ),
                        child: Wrap(
                          spacing: 14,
                          runSpacing: 4,
                          children: [
                            Text(
                              '${step['at']}',
                              style: TextStyle(color: muted, fontSize: 11),
                            ),
                            Text(
                              '${step['actor']}',
                              style: TextStyle(color: muted, fontSize: 11),
                            ),
                            Text(
                              "Step ${step['number']} · ${names[(step['number'] as int) - 1]} · ${step['status']}",
                              style: const TextStyle(fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
        ),
        const SizedBox(height: 8),
        Text(
          'Recorded steps stay with this attempt and device.',
          style: TextStyle(color: muted, fontSize: 11),
        ),
      ],
    );

    final heading = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'TEST BENCH / GUIDED TEST',
          style: TextStyle(color: accent, letterSpacing: 1, fontSize: 11),
        ),
        const SizedBox(height: 8),
        Text(
          'One step at a time.',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontSize: 28,
            fontWeight: FontWeight.w500,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'The next action, the expected result, and the evidence together.',
          style: TextStyle(color: muted),
        ),
      ],
    );
    final historyButton = OutlinedButton.icon(
      style: OutlinedButton.styleFrom(
        foregroundColor: colors.onSurface,
        side: BorderSide(color: outline),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
      onPressed: () {
        final target = historyKey.currentContext;
        if (target != null) {
          Scrollable.ensureVisible(
            target,
            duration: const Duration(milliseconds: 200),
          );
        }
      },
      icon: const Icon(Icons.history, size: 18),
      label: const Text('Device history'),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        LayoutBuilder(
          builder: (context, constraints) => constraints.maxWidth < 420
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    heading,
                    const SizedBox(height: 12),
                    historyButton,
                  ],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: heading),
                    const SizedBox(width: 12),
                    historyButton,
                  ],
                ),
        ),
        const SizedBox(height: 24),
        LayoutBuilder(
          builder: (context, constraints) => constraints.maxWidth < 600
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    deviceField,
                    const SizedBox(height: 12),
                    sequenceField,
                  ],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: deviceField),
                    const SizedBox(width: 12),
                    Expanded(child: sequenceField),
                  ],
                ),
        ),
        if (selected != null) ...[
          const SizedBox(height: 10),
          SelectableText(
            '${selected.id} · ${article?.role ?? 'Unknown role'} · ${selected.ownerId == null ? 'Unclaimed' : 'Claimed'}',
            style: TextStyle(color: muted, fontSize: 11),
          ),
        ],
        const SizedBox(height: 6),
        Text(
          '${guide['title']} · Local definition v${guide['revision']}',
          style: TextStyle(color: muted, fontSize: 11),
        ),
        if (viewing) ...[
          const SizedBox(height: 8),
          SelectableText(
            "Attempt ${report['id']} · ${s.active && report['outcome'] == 'Incomplete' ? 'In progress' : report['outcome']} · ${s.verifiedGenerations[report['id']] == report['generation'] ? 'Server verified' : 'Local only'}",
            style: TextStyle(color: muted, fontSize: 11),
          ),
        ],
        const SizedBox(height: 16),
        Divider(color: outline),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) => constraints.maxWidth < 560
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [timeline, action, evidence],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SizedBox(width: 180, child: timeline),
                    const SizedBox(width: 22),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [action, evidence],
                      ),
                    ),
                  ],
                ),
        ),
        if (s.active)
          TextButton(
            onPressed: c.cancelBench,
            child: const Text('Cancel attempt'),
          ),
        ExpansionTile(
          title: const Text('Prerequisites and tester guide'),
          children: [
            if (build != null)
              ListTile(
                title: const Text('Compatible firmware'),
                subtitle: SelectableText(
                  'Firmware ${build.version}\nSource ${build.source}\nExpected image ${build.artifact}',
                ),
              ),
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
        if (viewing) ...[
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
        Container(
          key: historyKey,
          child: Text(
            'Recorded attempts',
            style: Theme.of(context).textTheme.titleMedium,
          ),
        ),
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
