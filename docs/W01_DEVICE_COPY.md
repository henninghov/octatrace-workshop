# W01-D01 — Device registry and copying

27 October 2026. This bounded UI change precedes the agreed USB writer workflow.
Devices remains the complete registry, including Reserved and Provisioned units.
No database migration, identity allocation or device operation is needed.

## What changed

Device cards show LINK/CORE from the unit's exact article revision, plus the
article code/revision. Missing metadata displays Unknown device type instead of
borrowing another unit's type. Serial, UUID and provisioning/ownership status are
labelled separately. Wide windows use columns; narrower desktop windows stack
the fields. Open the device through its heading or chevron; selecting/copying a
field does not navigate.

The same selectable text and copy icon now serve device details, status/error
banners, diagnostic-result messages, raw diagnostic JSON and history UUIDs/reports.
The icon copies the exact full value without its label. Keyboard/text selection
can copy a chosen portion. Success gives brief feedback; clipboard failure keeps
the text available and offers manual-copy recovery.

## Dart walkthrough

1. [`deviceCard()`](../lib/ui/workshop_app.dart:580) joins each device's
   `revisionId` to the loaded article revisions. Its heading opens the selected
   device; the field controls keep that action separate. Existing data/state is
   displayed without a backend write or filtering out unfinished units.
2. [`CopyableText`](../lib/ui/copyable_text.dart:5) pairs Flutter's SelectableText
   with the existing Material copy icon. Its `value` is the displayed and copied
   text; `label` supplies the heading and accessible tooltip.
3. [`_copy()`](../lib/ui/copyable_text.dart:18) sends that value to Flutter's
   system clipboard adapter. Dart's `await` means the platform call may finish
   later. The mounted check prevents feedback from using a closed screen.
   Failure shows recovery guidance without changing the device or diagnostic.
4. [`notice()`](../lib/ui/workshop_app.dart:162), device details and history reuse
   the same control, so messages and identifiers have consistent selection/copy
   behavior. Existing diagnostic persistence and provisioning guards are unchanged.

## What the tests prove

The old list fails the regression because it lacks the type and copy controls.
Widget tests then verify exact Unicode/multiline copying, Cmd+A/C, partial keyboard
selection, clipboard failure, completion after screen disposal and long wrapping.
Registry tests prove copying does not open/modify a device, remains available
while work is busy, displays LINK/CORE/unknown metadata and both provisioning/
ownership states, and forwards the correct detail/status/diagnostic values.
Two new exact light/dark device-list baselines are visually inspected; existing
baselines are unchanged. The narrower desktop layout also passes.

Full gate: 73 Flutter tests plus configured startup, format/fatal-info analysis,
949/949 executable Dart lines (critical sources 100%). Branch coverage remains
unmeasured. Configured native build/reopen pass; the user confirms device type and both
copying methods work. Updated detail fields/copy controls are observed natively.
Actual results are recorded in the handoff and [receipt](evidence/w01-device-copy-results.json). Automated platform-channel tests
are separate from real macOS clipboard acceptance. No USB or hardware pass is
claimed. W01 provisioning and metadata mutation follow-ups remain open.

## Native acceptance

1. Sign in with a fresh magic link after reopening Workshop.
2. Open Devices. Confirm the existing unit shows LINK, its article revision,
   serial, UUID and Reserved / Unclaimed status.
3. Click each copy icon and paste into a local text field. Confirm the exact
   field value, without its label; the list must stay open.
4. Select a portion of the serial/UUID and press Cmd+C; paste and confirm only
   the selected text. Open the device through its heading/chevron.
5. Check selection/copy icons on its detail fields and existing status message.
   Existing failed diagnostics can be copied from Setup history; do not start a
   USB operation just to generate a message.
