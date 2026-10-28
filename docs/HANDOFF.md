# Workshop handoff

## W01-P02 software/native Passed; new-board Pending — 28 October 2026

Integrated profile-bound preparation with explicit consent, fresh authorization,
protected existing identities and durable retry evidence. Green/orange/red outcome
pills show SUCCESSFUL/PENDING/FAILED beside server confirmation. Gate151 + startup,
1,571/1,571 lines and macOS build pass. Native existing CORE verification skips
preparation, retains its key and shows SUCCESSFUL. Fresh-board erasure/continuation
awaits hardware. User requests commit/push on this feature branch.
[Canonical scope, walkthrough, evidence and next work](../../vectrc-app/docs/W01_IDENTITY_PREPARATION.md).

## F01-C01 CORE development USB acceptance Passed — 28 October 2026

CORE is supported end to end with matching article/build/proof roles. 132 tests +
startup, 1,448/1,448 measured Dart lines, analysis/format/goldens/macOS build pass.
Initial provisioning, repeat verification and final bfe040a8 update pass on one
physical T114 with the original identity/key retained. Registry is Provisioned /
Unclaimed; one reservation, three requests/completions. Canonical [scope, C++/Dart
walkthrough, exact evidence and remaining boundaries](../../vectrc-app/docs/F01_CORE_PROVISIONING.md) live in the app repo.
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
policy. [Walkthrough](W01_ENTRY_AND_PARTS.md).

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
[Walkthrough](W01_USB_PROVISIONING.md), [receipt](evidence/w01-usb-provisioning-results.json).

## Checkpoint publication and next session — 27 October 2026

User requests commit/push of the current foundation on
`feature/W01-provisioning-foundation`. Source still matches the accepted W01-D01
69-file test/build input manifest. Exclude generated Supabase CLI metadata and
local configuration/evidence from this first commit. No USB provisioning flow
integration or new native build is claimed.

Resume on 28 October: Workshop integration/recovery and quality gate, development
backend activation, then coordinated physical LINK provisioning and reboot/update
key-preservation acceptance. The canonical firmware code is now in its owning
repository with passing host/tooling and both target builds; it is not flashed.
[Agreed plan](../../vectrc-app/docs/F01_USB_PROVISIONING.md#agreed-plan-for-28-october-2026).

## W01-D01 device type and copying Passed — 27 October 2026

User prioritizes this UI pass before USB provisioning. Registry cards resolve
LINK/CORE from the exact article revision, with explicit unknown-type fallback.
Serial, UUID and provisioning/ownership status are labelled, selectable and have
copy icons. Headings/chevrons open devices; field copying keeps the list open.
The same controls serve detail fields, status/error banners and diagnostic/history
values. Exact full values or selected portions copy; failure offers manual recovery.
Wide/narrow desktop layouts and light/dark renders pass.

Final gate73 + configured startup, 949/949 executable Dart lines, format/fatal-info
analysis and configured macOS build pass. Existing visual baselines are unchanged;
two new registry renders are inspected. Native old screen was idle with empty USB
inputs before reopening. User signs in and confirms type, copy icons and text
selection/Cmd+C work. Updated detail fields/type/copy controls are observed. The
build is left signed in; UI navigation follows the user’s current work. No schema/cloud/device/firmware action, allocation or
commit/push. This bounded UI pass is accepted; full W01/USB writer
remains pending its coordinated storage/security/recovery design. [Dart walkthrough](W01_DEVICE_COPY.md),
[receipt](evidence/w01-device-copy-results.json).

## W01-R01 first LINK reservation Passed — 27 October 2026

Removed the redundant Hardware revision field from Workshop, its DTO/RPC and the
shared registry. The guarded new migration is applied to the approved development
project; the original deployed migration is unchanged. Empty-registry/no-pending-
journal preflight passes. One existing article and both user-created revisions
remain intact. The operator selects revision 2, signs in on the new build and
creates one first-LINK reservation. Native UI, read-only server check and Refresh
agree: one stable UUID/serial, Reserved / Unclaimed and one reservation event.
Real identifiers remain private; reuse this record rather than reserve again.

Host gate61 + startup, 902/902 Dart lines, format/analysis/native build; 55 Workshop
SQL assertions, populated-upgrade refusal and six Workshop races plus existing
suites/nine races pass. Prototype26/11 checks pass (simulated). Common firmware
plus separate persistent identity is agreed; per-device key/challenge-response is
proposed, not implemented. No firmware, USB write, keys or protection change.
W01 remains active for article/revision mutation idempotency and coordinated F01
writer/storage/key/recovery qualification. No commit/push.
[Walkthrough](W01_RESERVATION.md),
[receipt](evidence/w01-reservation-results.json).

## W01-AR01 native Save Passed — 27 October 2026

User signs in on the repaired build, creates the first LINK article using the
separate part inputs, and supplies its saved-card screenshot. A read-only hosted
check matches one article/revision, four component numbers and their quantities.
Native structured editor was visually inspected. The requested draft restoration
is superseded by the user's successful save; no agent Save or duplicate restoration.
Real inventory details remain in private ignored evidence. Software gate remains
60 tests + startup, 910/910 Dart lines and configured macOS build. This repair is
Passed; broader W01 provisioning and mutation idempotency remain in progress.

## W01-AR01 structured parts — 27 October 2026

The user cannot save a plain-language parts list and requests separate inputs.
Replaced the hidden delimiter format with explicit part number/description/quantity
rows, Add/remove controls and inline validation. Backend JSON/schema unchanged.
Red regression followed by full 60 tests + startup, 910/910 Dart lines, analysis,
format and configured macOS build. Synthetic dark render inspected; no real data
in fixtures. New build reopened; native sign-in/draft restoration and the actual
save remain pending. Live reload could not attach and was stopped without changing
the old app; the empty form was inspected before reopening. Screenshot values are
preserved in ignored private build data; part numbers are not invented.
[Walkthrough](W01_ARTICLE_INPUTS.md), [receipt](evidence/w01-article-input-results.json).
W01 stays in progress; no schema, device action, firmware change, commit or push.

## Hosted activation and magic-link acceptance — 26 October 2026

The approved shared migration is applied to the existing development backend;
the selected existing user has internal operator access. Hosted permission/RLS/
role checks pass, with no article/device/event rows created. The existing public
key is configured locally; no service key is in this app. Workshop's own callback
is registered while preserving all prior callbacks and the Auth site URL.

User selects magic links, superseding password login. The configured macOS build
passes 54 tests plus startup, 853/853 Dart executable lines, format/analysis/build.
Real acceptance Passed: user reports email-link return and Devices visible;
assistant observes the signed-in workspace on Provisioning after user navigation.
The user confirms no content has been added. Leave Workshop signed in/open.
No password change, physical identity allocation/write, actual USB diagnostic,
firmware installation, commit or push. Broader W01 remains in progress.

Read `W01_FOUNDATION.md` for request → PKCE/callback → verified identity → operator
check → registry data flow, invalid/expired/duplicate/logout recovery and exact
sign-in steps. Receipt: `evidence/w01-magic-link-results.json`. Logs:
`build/w01-magic-link-quality.log`, `build/w01-magic-link-build.log`.
Next: agree the first real article/revision/parts definition, complete idempotent
metadata mutations and coordinated F01 identity writer before physical setup.
Customer self-provisioning stays future scope.

## Earlier local foundation checkpoint

26 October 2026. W01 remains in progress. The actual project is now in
`/Users/henninghov/Sites/octatrace-workshop`, local branch
`feature/W01-provisioning-foundation`, origin `henninghov/octatrace-workshop`.
No commit/push. Temporary bootstrap code has been delivered to its owning project;
use this folder for subsequent development. Shared migrations live in the mobile
app repository on `feature/W01-workshop-registry`.

Local host acceptance: 44 Flutter tests plus configured-startup execution,
766/766 executable Dart lines (critical sources 100%), format/fatal-info analysis
and macOS debug build pass. The declaration-only ports file has no VM executable
lines and its exact hash is checked. No branch coverage claim. Native login and
original branding were visually inspected in the built app; unconfigured login
correctly stays disabled. `docs/evidence/w01-results.json` fingerprints all 60
code/test/build inputs. Logs are `build/w01-quality.log` and
`build/w01-macos-build.log`. Shared disposable DB tests pass 52 Workshop assertions
and 6 Workshop races plus existing suites/9 races. Prototype checks: 26 existing,
10 new foundation interactions, all simulated.

The configured startup test originally failed/hung on SDK cleanup in Flutter's
fake async clock. Constructing and disposing that real SDK in the real async zone
fixed the test; the final complete gate passes. Expanded earlier tests also found
and fixed a dialog-controller lifetime error and late-account operation races.

No hosted migration, operator grant, actual login/USB operation, permanent physical
identity allocation/write, firmware install or remote publication. The USB contract
still reports unprovisioned/null identity. Install and provision remains disabled;
reserve/diagnostic success never changes physical provisioning state. Article and
revision mutations need durable request IDs before production use. On uncertain
revision save, refresh and inspect before saving again.

Next: review/apply the shared migration to the intended development project and
admin-enable the existing account as an internal operator; agree the coordinated
F01 permanent identity writer/key storage and qualify interrupted install/readback/
reboot. Customer self-provisioning and multi-Mac packaging remain future scope.

Read `W01_FOUNDATION.md` for the plain-language code walkthrough, execution/data
flow, reasons, exact setup steps and acceptance limits. The existing design archive
is updated, preserving the prior version in its dated Revisions directory.
