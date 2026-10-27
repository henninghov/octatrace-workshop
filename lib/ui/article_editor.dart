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
      quantity = TextEditingController(text: '${value?['quantity'] ?? 1}');
  final int id;
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
  const ArticleEditor({super.key, this.existing});
  final ArticleRevision? existing;
  @override
  State<ArticleEditor> createState() => _ArticleEditorState();
}

class _ArticleEditorState extends State<ArticleEditor> {
  final _form = GlobalKey<FormState>();
  late final TextEditingController code, name, caseVersion;
  final _parts = <_PartInputs>[];
  int _nextPart = 0;
  bool _submitted = false;
  late String role;

  @override
  void initState() {
    super.initState();
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
            return null;
          },
        );
        final description = TextFormField(
          key: Key('part-${part.id}-description'),
          controller: part.description,
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
                'Add each component with its part number, description and quantity.',
              ),
              const SizedBox(height: 16),
              for (var i = 0; i < _parts.length; i++) _partRow(_parts[i], i),
              OutlinedButton.icon(
                onPressed: _parts.length < 1000
                    ? () => setState(() => _parts.add(_PartInputs(_nextPart++)))
                    : null,
                icon: const Icon(Icons.add, size: 18),
                label: const Text('Add part'),
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
