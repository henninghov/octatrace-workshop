# Workshop tasks

## W01-P02 software/native Passed; new-board Pending — 28 October 2026

Integrated profile-bound preparation with explicit consent, fresh authorization,
protected existing identities and durable retry evidence. Green/orange/red outcome
pills show SUCCESSFUL/PENDING/FAILED beside server confirmation. Gate151 + startup,
1,571/1,571 lines and macOS build pass. Native existing CORE verification skips
preparation, retains its key and shows SUCCESSFUL. Fresh-board erasure/continuation
awaits hardware. User requests commit/push on this feature branch.
[Canonical scope, walkthrough, evidence and next work](../vectrc-app/docs/W01_IDENTITY_PREPARATION.md).

## F01-C01 CORE development USB acceptance Passed — 28 October 2026

CORE is supported end to end with matching article/build/proof roles. 132 tests +
startup, 1,448/1,448 measured Dart lines, analysis/format/goldens/macOS build pass.
Initial provisioning, repeat verification and final bfe040a8 update pass on one
physical T114 with the original identity/key retained. Registry is Provisioned /
Unclaimed; one reservation, three requests/completions. Canonical [scope, C++/Dart
walkthrough, exact evidence and remaining boundaries](../vectrc-app/docs/F01_CORE_PROVISIONING.md) live in the app repo.
Current changes are local/uncommitted. Broader W01 and production scope remain separate.

## W01-U01 shared parts and separate device entry — 28 October 2026

The requested UI slice passes 126 tests + configured startup, 1,432/1,432 measured
Dart lines, format/fatal-info analysis and the configured macOS build. New device
reserves from article/revision/class and opens the exact returned identity; Existing
device only selects/continues an existing record. Articles offer searchable shared
parts and Create part; canonical identity is fixed and quantities are per revision.
Native sign-in, navigation, chooser/search/draft/cancel are verified without saving
or reserving real records. Workshop is left signed in on Devices. No migration,
deployment, firmware change or publication. CORE provisioning remains unsupported.
Prototype updated; syntax checks pass, browser runtime not run due local-file URL
policy. [Walkthrough](docs/W01_ENTRY_AND_PARTS.md).

## W01-P01 USB provisioning integration — 28 October 2026

Software implementation passes 115 tests + configured startup, 1,324/1,324 Dart
lines, format/fatal-info analysis and the configured macOS build. Select registry
device/USB target/qualified build, install/prove/reboot, persist proof before
server upload, then require fresh registry confirmation. Cancel/logout/retry and
real-file/subprocess recovery are tested. New light/dark renders inspected.
User screenshots pass native sign-in/selector discovery: LINK detected in normal
USB mode and two qualified builds listed; newest76d913b3 identified. No physical
install/key creation/new reservation or provisioning completion performed by agent.
Server verifier deployment and physical acceptance remain next; W01/F01 stay in
progress. Firmware unchanged. No commit/push in this pass.
[Walkthrough](docs/W01_USB_PROVISIONING.md), [receipt](docs/evidence/w01-usb-provisioning-results.json).

## Next session — 28 October 2026

USB provisioning/recovery integration is next within W01, followed by development
backend activation and physical acceptance. Reuse the first LINK reservation.
[Canonical plan](../vectrc-app/docs/F01_USB_PROVISIONING.md#agreed-plan-for-28-october-2026).
Current publication is a foundation checkpoint, not completed physical provisioning.

## W01-D01 device type and copying Passed — 27 October 2026

Registry shows device type and selectable/copy-icon serial, UUID and status.
Details/status/diagnostics reuse the same controls. Gate73 + startup, 949/949 Dart
lines, format/analysis/native build and inspected light/dark renders pass. User
passes native sign-in, device type and both clipboard methods. No DB or device action.
This pass precedes USB provisioning. [Handoff](docs/HANDOFF.md).

## W01-R01 registry reservation Passed — 27 October 2026

Workshop uses article revision as the complete build; independent hardware field
removed. Guarded migration applied; 61 tests + startup, 902/902 Dart lines, native
build, 55 SQL assertions, legacy guard and six races pass. First reusable LINK
reservation verified on operator-selected revision 2: Reserved / Unclaimed, one
identity/event after Refresh. No physical programming or keys. W01 stays active;
next qualify F01 identity writer/storage/security and metadata mutation requests.
[Handoff](docs/HANDOFF.md).

W01-AR01 Passed — 27 October 2026: user saves the first real article with four
parts in the repaired form; screenshot and read-only hosted check agree. The
agent did not create a duplicate or save inventory. Broader W01 remains active.

- W01-AR01 — software passed: structured part rows fix the article-entry blocker.
  60 tests + startup, 910/910 Dart lines and configured native build pass. Native
  retry/real save pending operator part numbers. See docs/W01_ARTICLE_INPUTS.md.

- W01 — in progress: internal login/operator check, articles/revisions, registry
  reservation, shared USB diagnostics and retained evidence implemented. Host gate
  passes 54 tests + configured startup, 853/853 Dart lines and macOS debug build.
- Next within W01: hosted schema/operator setup and real magic-link login Passed. Remaining: durable article/revision
  mutation requests; coordinated firmware identity writer/storage/key decisions,
  guarded installation/readback/reboot recovery and physical acceptance.
- Later: customer self-provisioning with organization/device-scoped roles, batch
  production, inventory, field monitoring, support and multi-Mac packaging.

Canonical hardware identities: provisioning.devices. One existing Supabase account
UUID may use both apps; operator access does not claim device ownership. Devices
leave provisioned and unclaimed; mobile onboarding claims the existing identity.
