import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:octatrace_workshop/services/evidence_journal.dart';

import 'widget_test.dart' as f;

void main() {
  test('control verification survives reopen and remains bound to account and exact immutable proof', () async {
    final root = await Directory.systemTemp.createTemp(
      'control-proof-receipt-',
    );
    addTearDown(() => root.delete(recursive: true));
    final journal = EvidenceJournal(root);
    final record = {
      'id': '40000000-0000-4000-8000-000000000001',
      'report': {'public_key': 'synthetic'},
    };
    expect(await journal.controlStorageConfirmed(f.actor, record), false);
    await journal.confirmControlStorage(f.actor, record);
    await journal.confirmControlStorage(f.actor, record);
    final reopened = EvidenceJournal(root);
    expect(await reopened.controlStorageConfirmed(f.actor, record), true);
    expect(await reopened.controlStorageConfirmed(f.other, record), false);
    expect(
      await reopened.controlStorageConfirmed(f.actor, {
        ...record,
        'report': {'public_key': 'changed'},
      }),
      false,
    );
    final receipt = (await Directory(
      '${root.path}/${f.actor}/control-confirmations',
    ).list().toList()).whereType<File>().single;
    await receipt.writeAsString('damaged receipt');
    expect(await reopened.controlStorageConfirmed(f.actor, record), false);
    await expectLater(
      reopened.confirmControlStorage(f.actor, record),
      throwsFormatException,
    );
    expect(await receipt.readAsString(), 'damaged receipt');
  });
}
