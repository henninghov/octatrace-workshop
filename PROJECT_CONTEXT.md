# Workshop context

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

26 October 2026. W01 is in progress. Separate Flutter macOS operator application,
owned by henninghov/octatrace-workshop. Existing Supabase accounts use magic-link sign-in and need server-managed
operator access. The approved development registry migration is applied and the
selected existing account is enabled; real email return is now Passed by user confirmation on the configured macOS build. Device claiming belongs to mobile onboarding;
Workshop prepares units with firmware/identity and leaves them unclaimed.

Confirmed model: device UUID, serial, article_id and immutable article_revision_id.
D/R/O prefixes plus twelve decimal digits share one numeric sequence. Internal
macOS builds may run outside App Sandbox to reuse existing local Python USB tools.
Multiple-Mac installation is future scope. Use the supplied existing prototype in
Documents/Vectrc/Octatrace Workshop as the design source.

Backend migrations and shared decisions remain in the mobile app repository.
The current firmware USB contract cannot write permanent identity; this is an
explicit remaining dependency, not a successful provisioning implementation.

Customer self-provisioning is deferred. This version authorizes internal Octatrace
operators only; future customer roles require organization/device-scoped access.
