import 'package:flutter/material.dart';

import '../domain/registry.dart';

final class ArticleDraft {
  const ArticleDraft(
    this.code,
    this.name,
    this.role,
    this.caseVersion,
    this.parts,
  );
  final String code, name, role, caseVersion;
  final List<Json> parts;
}

class _PartInputs {
  _PartInputs(this.id, [Json? value])
    : number = TextEditingController(text: value?['part_number'] as String?),
      description = TextEditingController(
        text: value?['description'] as String?,
      ),
      shared = value != null,
      quantity = TextEditingController(text: '${value?['quantity'] ?? 1}');
  final int id;
  bool shared;
  final TextEditingController number, description, quantity;
  void dispose() {
    number.dispose();
    description.dispose();
    quantity.dispose();
  }

  Json toJson() => {
    'part_number': number.text.trim(),
    'description': description.text.trim(),
    'quantity': int.parse(quantity.text.trim()),
  };
}

/// Each part has explicit fields; the operator never types a serialization format.
class ArticleEditor extends StatefulWidget {
  const ArticleEditor({
    super.key,
    this.existing,
    this.availableParts = const [],
  });
  final ArticleRevision? existing;
  final List<Json> availableParts;
  @override
  State<ArticleEditor> createState() => _ArticleEditorState();
}

class _ArticleEditorState extends State<ArticleEditor> {
  final _form = GlobalKey<FormState>();
  late final TextEditingController code, name, caseVersion;
  final _parts = <_PartInputs>[];
  late final List<Json> _catalogue;
  int _nextPart = 0;
  bool _submitted = false;
  late String role;

  @override
  void initState() {
    super.initState();
    final byNumber = <String, Json>{};
    for (final part in [...widget.availableParts, ...?widget.existing?.parts]) {
      byNumber[part['part_number'] as String] = part;
    }
    _catalogue = byNumber.values.toList()
      ..sort(
        (a, b) =>
            (a['part_number'] as String).compareTo(b['part_number'] as String),
      );
    code = TextEditingController(text: widget.existing?.code);
    name = TextEditingController(text: widget.existing?.name);
    caseVersion = TextEditingController(text: widget.existing?.caseVersion);
    for (final value in widget.existing?.parts ?? <Json>[]) {
      _parts.add(_PartInputs(_nextPart++, value));
    }
    if (_parts.isEmpty) _parts.add(_PartInputs(_nextPart++));
    role = widget.existing?.role ?? 'Link';
  }

  @override
  void dispose() {
    for (final field in [code, name, caseVersion]) {
      field.dispose();
    }
    for (final part in _parts) {
      part.dispose();
    }
    super.dispose();
  }

  String? _required(String? value, String label, int limit) {
    final text = value?.trim() ?? '';
    if (text.isEmpty) return 'Enter $label.';
    if (text.length > limit) return 'Use $limit characters or fewer.';
    return null;
  }

  void _remove(_PartInputs part) {
    setState(() => _parts.remove(part));
    // Dispose only after the removed TextFormFields have unmounted.
    WidgetsBinding.instance.addPostFrameCallback((_) => part.dispose());
  }

  Future<void> choosePart() async {
    final selected = await showDialog<Json>(
      context: context,
      builder: (_) => _PartPicker(
        parts: _catalogue,
        listed: _parts
            .where((p) => p.shared)
            .map((p) => p.number.text.trim())
            .toSet(),
      ),
    );
    if (selected == null || !mounted) return;
    setState(() {
      final matchingDraft = _parts
          .where(
            (p) => !p.shared && p.number.text.trim() == selected['part_number'],
          )
          .firstOrNull;
      final blank =
          matchingDraft ??
          _parts
              .where(
                (p) =>
                    p.number.text.trim().isEmpty &&
                    p.description.text.trim().isEmpty,
              )
              .firstOrNull;
      final row = blank ?? _PartInputs(_nextPart++);
      if (blank == null) _parts.add(row);
      row.number.text = selected['part_number'] as String;
      row.description.text = selected['description'] as String;
      row.shared = true;
    });
  }

  void save() {
    setState(() => _submitted = true);
    final invalid = _form.currentState!.validateGranularly();
    if (invalid.isNotEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) Scrollable.ensureVisible(invalid.first.context);
      });
      return;
    }
    Navigator.pop(
      context,
      ArticleDraft(
        code.text.trim(),
        name.text.trim(),
        role,
        caseVersion.text.trim(),
        _parts.map((p) => p.toJson()).toList(),
      ),
    );
  }

  Widget _partRow(_PartInputs part, int index) => Padding(
    key: ValueKey(part.id),
    padding: const EdgeInsets.only(bottom: 16),
    child: LayoutBuilder(
      builder: (context, constraints) {
        final number = TextFormField(
          key: Key('part-${part.id}-number'),
          controller: part.number,
          readOnly: part.shared,
          decoration: const InputDecoration(
            labelText: 'Part number',
            errorMaxLines: 3,
          ),
          validator: (value) {
            final required = _required(value, 'a part number', 100);
            if (required != null) return required;
            if (_parts
                    .where((p) => p.number.text.trim() == value!.trim())
                    .length >
                1) {
              return 'Already listed. Use one row with the total quantity.';
            }
            if (!part.shared &&
                _catalogue.any((p) => p['part_number'] == value!.trim())) {
              return 'Part already exists. Choose it from existing parts.';
            }
            return null;
          },
        );
        final description = TextFormField(
          key: Key('part-${part.id}-description'),
          controller: part.description,
          readOnly: part.shared,
          decoration: const InputDecoration(
            labelText: 'Description',
            errorMaxLines: 2,
          ),
          validator: (value) => _required(value, 'a description', 240),
        );
        final quantity = SizedBox(
          width: 100,
          child: TextFormField(
            key: Key('part-${part.id}-quantity'),
            controller: part.quantity,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'Quantity',
              errorMaxLines: 4,
            ),
            validator: (value) {
              final text = value?.trim() ?? '';
              final amount = int.tryParse(text);
              if (!RegExp(r'^[0-9]+$').hasMatch(text) ||
                  amount == null ||
                  amount < 1 ||
                  amount > 1000000) {
                return 'Use a whole number from 1 to 1000000.';
              }
              return null;
            },
          ),
        );
        final remove = IconButton(
          tooltip: 'Remove part ${index + 1}',
          onPressed: _parts.length > 1 ? () => _remove(part) : null,
          icon: const Icon(Icons.remove_circle_outline),
        );
        if (constraints.maxWidth < 600) {
          return Column(
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(child: number),
                  const SizedBox(width: 12),
                  quantity,
                  remove,
                ],
              ),
              const SizedBox(height: 12),
              description,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(flex: 3, child: number),
            const SizedBox(width: 12),
            Expanded(flex: 5, child: description),
            const SizedBox(width: 12),
            quantity,
            remove,
          ],
        );
      },
    ),
  );

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(
      widget.existing == null ? 'New article' : 'New immutable revision',
    ),
    content: SizedBox(
      width: 720,
      child: SingleChildScrollView(
        child: Form(
          key: _form,
          autovalidateMode: _submitted
              ? AutovalidateMode.onUserInteraction
              : AutovalidateMode.disabled,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (widget.existing == null) ...[
                TextFormField(
                  key: const Key('article-code'),
                  controller: code,
                  decoration: const InputDecoration(labelText: 'Article code'),
                  validator: (value) => _required(value, 'an article code', 80),
                ),
                const SizedBox(height: 16),
                TextFormField(
                  key: const Key('article-name'),
                  controller: name,
                  decoration: const InputDecoration(labelText: 'Name'),
                  validator: (value) => _required(value, 'a name', 160),
                ),
                const SizedBox(height: 16),
                DropdownButtonFormField<String>(
                  initialValue: role,
                  decoration: const InputDecoration(labelText: 'Product'),
                  items: ['Link', 'Core']
                      .map(
                        (r) => DropdownMenuItem(
                          value: r,
                          child: Text(r.toUpperCase()),
                        ),
                      )
                      .toList(),
                  onChanged: (r) => role = r!,
                ),
                const SizedBox(height: 16),
              ],
              TextFormField(
                key: const Key('article-case'),
                controller: caseVersion,
                decoration: const InputDecoration(labelText: 'Case version'),
                validator: (value) => _required(value, 'a case version', 100),
              ),
              const SizedBox(height: 24),
              Text('Parts', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 6),
              const Text(
                'Reuse a shared part or create a new one. Quantities apply to this revision.',
              ),
              const SizedBox(height: 16),
              for (var i = 0; i < _parts.length; i++) _partRow(_parts[i], i),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  OutlinedButton.icon(
                    onPressed: _catalogue.isNotEmpty && _parts.length < 1000
                        ? choosePart
                        : null,
                    icon: const Icon(Icons.search, size: 18),
                    label: const Text('Choose existing part'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _parts.length < 1000
                        ? () => setState(
                            () => _parts.add(_PartInputs(_nextPart++)),
                          )
                        : null,
                    icon: const Icon(Icons.add, size: 18),
                    label: const Text('Create part'),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              const Text(
                'Shared part numbers and descriptions are fixed. Create a new part for a replacement.',
              ),
            ],
          ),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(onPressed: save, child: const Text('Save revision')),
    ],
  );
}

class _PartPicker extends StatefulWidget {
  const _PartPicker({required this.parts, required this.listed});
  final List<Json> parts;
  final Set<String> listed;
  @override
  State<_PartPicker> createState() => _PartPickerState();
}

class _PartPickerState extends State<_PartPicker> {
  String query = '';
  @override
  Widget build(BuildContext context) {
    final matches = widget.parts
        .where(
          (part) => '${part['part_number']} ${part['description']}'
              .toLowerCase()
              .contains(query),
        )
        .toList();
    return AlertDialog(
      title: const Text('Choose existing part'),
      content: SizedBox(
        width: 620,
        height: 360,
        child: Column(
          children: [
            TextField(
              key: const Key('part-search'),
              autofocus: true,
              decoration: const InputDecoration(
                labelText: 'Search part number or description',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: (value) =>
                  setState(() => query = value.trim().toLowerCase()),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: matches.isEmpty
                  ? const Center(child: Text('No matching parts.'))
                  : ListView(
                      children: [
                        for (final part in matches)
                          ListTile(
                            title: Text(
                              '${part['part_number']} — ${part['description']}',
                            ),
                            subtitle:
                                widget.listed.contains(part['part_number'])
                                ? const Text('Already in this revision')
                                : null,
                            enabled: !widget.listed.contains(
                              part['part_number'],
                            ),
                            onTap: () => Navigator.pop(context, part),
                          ),
                      ],
                    ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Back to article'),
        ),
      ],
    );
  }
}
