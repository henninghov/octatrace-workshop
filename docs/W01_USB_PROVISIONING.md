# W01-P01 — Workshop USB provisioning integration

## W01-P02 preparation/status software Passed — 28 October 2026

First-time preparation is part of Install / Verify and provision. Blank or intact
storage proceeds; unknown uncommitted storage on a supported profile requires
Prepare and continue, followed by fresh authorization and live reinspection.
Existing identities, pending records, registered keys and saved proofs are protected.
Profiles stay in the firmware-owned host tools; unsupported boards stop.

Requested green SUCCESSFUL, orange PENDING and red FAILED labels follow the actual
device/account-bound attempt. Failed proof uploads retain their evidence for retry.
151 tests + startup, 1,571/1,571 Dart lines, analysis/format/goldens/macOS build pass.
Native existing CORE verification has no preparation dialog and shows SUCCESSFUL;
original key and actual signed reboot proofs verify. New-board preparation Pending.

[Canonical Python/Dart walkthrough and new-board checklist](../../vectrc-app/docs/W01_IDENTITY_PREPARATION.md) ·
[Current source-bound software receipt](evidence/w01-identity-preparation-results-20261028.json).


## CORE development USB acceptance Passed — 28 October 2026

Workshop accepts matching development LINK or CORE articles, firmware and proofs.
The CORE slice passes 132 tests + configured startup, 1,448/1,448 measured Dart
lines, format/analysis, exact goldens and the configured macOS build. Native CORE
selection offers only CORE images and retains its existing reservation. First
provisioning, repeat verification and update e3d3c2b4→bfe040a8 pass on one T114.
Original UUID/serial/revision/hardware/key remain unchanged; all six signatures
verify across reboots. Server and USB agree: Provisioned / Unclaimed, one
reservation, three requests with exactly three completion events.

The first unit's unknown identity bytes required separately approved two-page
initialization. Normal provisioning/updates never erase identity. CORE currently
has no phone pairing or display interface; the blank screen is expected.

[Canonical C++/Dart walkthrough and physical receipt](../../vectrc-app/docs/F01_CORE_PROVISIONING.md) ·
[Workshop software/source receipt](evidence/w01-core-provisioning-software-20261028.json).
Earlier LINK-only entries below describe their dated checkpoints.

## Accepted LINK checkpoint and UI follow-up — 28 October 2026

The first LINK now passes original identity/key preservation through a genuine
firmware update, valid proofs across reboot, server confirmation and final captured
saved phone Connect/Refresh. The firmware-owned Python runner repairs lost reboot
replies: 82 tooling tests and an actual automatic recovery pass. Installed firmware
remains 0.2.0/source99038b85; the original untraced saved-pairing retry stays open.
[Canonical evidence/repair walkthrough](../../vectrc-app/docs/F01_USB_PROVISIONING.md).

The following UI slice separates New device/Existing device and adds reusable parts
selection, with native review and 126-test gate. See [the current walkthrough](W01_ENTRY_AND_PARTS.md).
Earlier dated software/physical-pending entries below retain their historical state.

## First provisioning Passed; post-completion display corrected — 28 October 2026

The operator completes Verify and provision on the original reservation. Workshop,
the server and current USB readback agree: Provisioned / Unclaimed, one completed
event, same UUID/serial/revision and matching public key. Both real P-256 proofs
verify independently with different boot nonces. The approved initialization
preceding this created no key and verified unchanged Bluetooth bond bytes.
[Physical receipt](../../vectrc-app/docs/evidence/w01-first-provisioned-link-20261028.json).

The native result exposed a misleading hardware-conflict warning after selectors
were cleared. A new widget regression reproduces that exact reopen-completed-device
path before the fix. [ProvisioningPanel](../lib/ui/provisioning_panel.dart) now
considers hardware conflict only when a USB target is actually selected. The
existing separate target/build checks still disable Verify with no selection.
A selected different unit still warns and cannot proceed. This is a Dart boolean
guard change; the controller, proof upload and security rules are unchanged.

Final gate:116 tests + configured startup,1,325/1,325 lines, format/fatal-info
analysis, original light/dark golden checks and configured macOS build pass.
The newly built native UI is not relaunched yet; the completed session is retained.
Firmware99038b85 adds an actual-adapter test that maintenance after key commit is
refused with all storage/key bytes unchanged.132 case executions,78 tooling tests,
2,124/2,124 lines, both target builds and source-bound qualification pass. Its only
changed source input is that test; the embedded build ID makes it a distinct
firmware artifact for the remaining update-preservation acceptance.

Next: receive the requested phone Connect/Refresh result; reopen this corrected
Workshop build; install qualified99038b85 through Workshop and verify the existing
identity/key before/after update and reboot. Never initialize the Ready identity.
[Final software and exact native inputs](../../vectrc-app/docs/evidence/w01-provisioning-final-software-20261028.json).


## Bounded recovery candidate ready — 28 October 2026

The user approves preparing/testing recovery for the first LINK's unknown
identity-page contents and explicitly requires bootloader preservation. Candidate
9cbd7d20 is qualified:132 portable cases,78 tooling tests,2,124/2,124 firmware
lines, full recovery branch coverage and both role builds. It permits erasing
only the two identity pages, checks every slot for an existing identity, verifies
blank storage and compares Bluetooth bonds locally. No physical erase has run.

Workshop's matching profile pins pass115 tests + configured startup,1,324/1,324
lines, format/analysis and macOS build. Its normal process allowlist has no
initialization action; the one-time maintenance command is separate. The existing
native error session has not been relaunched. Reuse the existing reservation and
select the qualified common firmware after the coordinated recovery.
[Walkthrough and constraints](../../vectrc-app/docs/F01_USB_PROVISIONING.md#recovery-code-walkthrough-and-software-results).
[Candidate receipt](../../vectrc-app/docs/evidence/f01-bounded-recovery-candidate-20261028.json).


## First physical install and storage diagnostic — 28 October 2026

The server verifier is deployed and read back. Workshop installed source76d913b3
on the confirmed LINK; identity setup then refused storage Fault before key
generation. The existing reservation remains Reserved / Unclaimed, one attempt,
no key/completion. Do not repeat the stale Install selection or allocate another
identity. See the canonical [F01 diagnosis and walkthrough](../../vectrc-app/docs/F01_USB_PROVISIONING.md#first-physical-attempt-and-diagnostic-walkthrough--28-october-2026).

The separate read-only storage command is now pinned in the firmware/app/Workshop
consumers. Workshop's only additional Dart change is those expected file hashes;
the process allowlist still exposes the original operator flow. A new full gate
passes 115 tests + configured startup, 1,324/1,324 lines, analysis/format and native
build. This does not constitute physical diagnostic or provisioning acceptance.
[Source-bound follow-up receipt](../../vectrc-app/docs/evidence/f01-storage-diagnostic-software-20261028.json).


28 October 2026. Software implementation and configured macOS build are ready for
review. Native sign-in and USB/build discovery are Passed by the user's supplied
screenshots: LINK is detected in normal USB mode and two qualified builds appear. Server verifier deployment and physical installation/key
preservation are separate next steps; W01/F01 are not physically complete.

## What the operator does

1. Sign in. Open Devices and select the existing reserved development LINK.
2. Connect that LINK directly by USB. Click **Refresh USB and firmware**.
3. Select the physical USB device and the qualified LINK firmware build.
4. For a new install, enter LINK's usual USB bootloader mode and refresh/select
   again. Click **Install and provision** only during the coordinated physical run.
   Normal USB mode offers **Verify and provision** for a previous installation.
5. Wait for identity/proof, reboot verification, server confirmation and refreshed
   registry status. Open **Details** to copy the exact build/public proof fields.

Only unclaimed D-class LINK devices are supported by this first writer. Unknown,
missing, conflicting or stale targets/builds cannot enable installation. Firmware
compilation remains a development task. Shared release/changelog management is
future work; this selector discovers locally qualified development bundles.

## Dart walkthrough: selection to confirmed registry

[ProvisioningPanel](../lib/ui/provisioning_panel.dart) uses the existing Workshop
layout, fonts, logo and selectable/copyable fields. It holds the operator's target
and build selections. Missing options remain explicit; the UI does not choose a
different physical unit automatically. Raw proof/hash information is under Details.
[WorkshopShell](../lib/ui/workshop_app.dart) links the registry selection to this
panel. The older diagnostic adapter path remains available to legacy fixtures;
the configured native app uses the new provisioning panel.

The plain models in [provisioning.dart](../lib/domain/provisioning.dart) validate
inventory/build identifiers and reject duplicate choices. They contain no USB or
Supabase calls. [DeviceRecord](../lib/domain/registry.dart) now reads the database's
optional hardware binding. That prevents selecting a unit different from the one
already associated with a reservation.

[WorkshopController.provision](../lib/domain/workshop_controller.dart) runs the
steps sequentially with Dart `Future`/`await`: each dependent step waits for the
previous one. It captures the initiating account and an operation generation.
Logout changes that generation, so late work cannot restore the signed-out UI or
upload into another account. Cancellation is checked before subsequent writes.

Before contacting the server or writing hardware, the controller stores a stable
request ID using the existing real-file [EvidenceJournal](../lib/services/evidence_journal.dart).
Retry with the same reservation, physical unit and build reuses that ID. The
server then rechecks operator access and the immutable device/build binding.
A conflicting response stops before USB. A completed server attempt reuses its
saved proof without reflashing or generating a key.

[ProcessProvisioningRunner](../lib/services/provisioning_runner.dart) checks the
consumer's exact P1 contract pins, then starts the firmware-owned Python CLI
without a shell. USB discovery, application-only install guards, key generation,
proof validation and reboot/key-preservation checks remain in
[the firmware tools](../../octatrace-firmware/tools/provision.py). Dart does not
reimplement their protocol/cryptography. Input contains only public attempt
fields, never an access token or device private key. Output/deadlines are bounded;
Cancel terminates the owned process and escalates if needed. Public stdout/stderr
from writing/verification steps is retained in a private per-step directory under
the initiating account's `usb/adapter` evidence folder. Firmware proof checkpoints
remain under that account's `usb` folder, including after cancellation.

Before uploading, the controller sorts the flat proof fields into a stable local
record. This avoids treating JSON key-order differences as changed evidence.
The real-file journal saves that record first, including a late successful result
after cancellation/logout. A backend outage leaves it pending.

[SupabaseGateway](../lib/services/supabase_gateway.dart) calls the operator-checked
begin RPC and the `workshop-provisioning` server verifier with the initiating
user's token. It never calls service-only completion directly. Expired/revoked
access, a missing verifier, malformed replies or the wrong returned device cannot
confirm provisioning. Server confirmation must be followed by a fresh registry
read showing Provisioned with the matching hardware binding before local evidence
is acknowledged. Missing or disagreeing readback retains the outbox record.

**Retry evidence upload** sends the saved report again, without USB, a new
reservation or another identity write. The same server idempotency key is used.
Failed/interrupted attempts retain their reservation, server attempt and local
runner evidence. Cancellation never erases a committed identity/key. Signing in
again clears previous account presentation before loading that account's records.

## What the tests establish

- Real file save/reopen and the same request/proof after retry; reordered JSON
  fields remain the same record. Confirmation must actually refresh the registry.
- Bootloader install precedes proof; normal mode verifies an existing install.
  Wrong role/class/owner/hardware and every mismatched server binding stop early.
- Lost server responses and missing/revoked verification retain evidence. Upload
  retry needs no connected device. Logout during begin, proof, upload, refreshed
  registry and discovery cannot expose/acknowledge another account's work.
- Cancel during authorization, install or proof prevents later operations; a late
  valid proof stays in its original account. No claim that killing a host process
  reverses already committed device flash.
- Real synthetic subprocesses verify contract mismatches, bounded arguments/
  stdin/output, no credential forwarding, private diagnostics, failed results,
  process-start cancellation, SIGTERM/SIGKILL and timeout behavior.
- SDK HTTP fixtures verify user-authenticated requests, service-only completion
  remaining inaccessible to the desktop, expired/revoked access and malformed or
  late-session replies. These fixtures do not claim a hosted verifier execution.
- Selectors, empty/missing/mismatched hardware/builds, progress, Cancel, upload
  retry, copyable details and exact light/dark snapshots use synthetic inventory.
  Original assets are unchanged. No new Figma inspection is claimed.

The full gate passes **115 tests plus configured startup**, format, fatal-info
analysis and **1,324/1,324 measured Dart lines**. Branch instrumentation remains
unavailable; named failure/race tests provide behavior evidence. The configured
macOS debug build passes and opens the sign-in screen. The two new renders are
inspected with real Excon/Material fonts and fully painted original branding;
older baselines are retained unchanged. The initially stalled widget test was a
fake-clock teardown wait and was corrected; interrupted runs are not passes.

[Source-bound software receipt](evidence/w01-usb-provisioning-results.json).
Current code is local/uncommitted on `feature/W01-provisioning-foundation` over
`044c9e2`. Firmware remains unchanged at `dac68e5` / source76d913b3….

## Remaining acceptance

Native signed-in USB/build discovery is Passed. Deploy/verify the server verifier,
then perform the coordinated real-device install, reboot/update key preservation
and current Bluetooth Connect/Refresh smoke. No actual firmware installation,
key generation, new reservation or provisioning completion has been performed by
this implementation pass. Shared migration was already deployed by the user.
Metadata mutation idempotency and release/changelog management remain separate
follow-ups. Keep full W01/F01 in progress until their required acceptance is met.

Native discovery acceptance uses private real-registry screenshots, not the synthetic
goldens. Latest candidate76d913b3 is identified for the operator; installation and
identity proof are not exercised by discovery. Original reservation remains
Reserved / Unclaimed in the supplied screenshot.
