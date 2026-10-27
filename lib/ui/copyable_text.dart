import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Select part of the value, or copy its exact full contents with one button.
class CopyableText extends StatelessWidget {
  const CopyableText({
    super.key,
    required this.label,
    required this.value,
    this.showLabel = true,
    this.style,
  });

  final String label, value;
  final bool showLabel;
  final TextStyle? style;

  Future<void> _copy(BuildContext context) async {
    String message;
    try {
      await Clipboard.setData(ClipboardData(text: value));
      message = '$label copied';
    } catch (_) {
      message = 'Could not copy. Select the text and copy it manually.';
    }
    if (!context.mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (showLabel) Text(label, style: Theme.of(context).textTheme.labelSmall),
      Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: SelectableText(value, style: style),
            ),
          ),
          IconButton(
            tooltip: 'Copy $label',
            onPressed: () => _copy(context),
            icon: Icon(Icons.content_copy, size: 18, color: style?.color),
          ),
        ],
      ),
    ],
  );
}
