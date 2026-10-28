# Octatrace Workshop

Current checkpoint: first-time storage inspection/preparation is integrated with
a one-time Prepare and continue dialog. SUCCESSFUL (green), PENDING (orange) and
FAILED (red) appear beside server confirmation. Existing-device verification is
Passed; first-time preparation on a new board is Pending.
[Current walkthrough and limits](../vectrc-app/docs/W01_IDENTITY_PREPARATION.md).


Internal Flutter macOS application for device preparation and diagnostics.

Active scope: magic-link login, server-managed operator access, articles and
immutable revisions, device identity reservation, USB readback and private evidence.
Serials: D development, R release candidate, O production; twelve digits and one
shared numeric sequence across all classes and LINK/CORE.

Run with the same pinned Flutter 3.47.6 / Dart 3.13.5 SDK as the mobile app:

```sh
flutter pub get
flutter run -d macos --dart-define-from-file=config/development.local.json
```

Copy `config/development.example.json` to the ignored local file and configure the
existing development Supabase URL, publishable key and local firmware checkout.
The application never receives a service key. Sessions and the pending PKCE
verifier are memory-only. Keep Workshop open while clicking the email on this Mac;
request a new link after restarting the app.

Canonical backend migrations remain in the mobile app repository. The registry
and article-revision simplification migrations are applied to development; see
`docs/W01_RESERVATION.md`. Original foundation:
`supabase/migrations/20261026180000_workshop_registry.sql`. It is applied to the approved development project, and the selected existing
account has internal operator access. Customer accounts cannot grant this role.
The ignored local config is populated with the existing publishable key.
Workshop's callback is registered without changing the mobile callback.

Workshop integrates the firmware-owned P1 USB CLI for target/build discovery,
application-only installation, permanent identity/proof and reboot verification.
Proofs are saved locally before authenticated server confirmation and a fresh
registry read. Cancel/logout and upload retry preserve the same reservation and
pending evidence. Current USB scope: unclaimed development LINK and CORE; the first provisioned unit, server
confirmation, firmware-update identity preservation and final saved phone reconnect
are verified. The earlier untraced Bluetooth retry observation remains open. See
[the USB provisioning walkthrough](docs/W01_USB_PROVISIONING.md).

The existing clickable prototype is retained in `design/Octatrace Workshop.html`,
with editable source in `design/prototype.html`. New flows are explicitly simulated.
They extend the user's existing Workshop design rather than replace it.

Shared product/security/quality decisions remain in the mobile app repository.
Read `docs/W01_FOUNDATION.md` for the code walkthrough, backend setup and limits.
Latest host checks pass: 151 tests + configured startup, 1,571/1,571 measured
Dart lines and configured macOS debug build. W01 remains in progress for metadata mutation
idempotency and physical provisioning. See `docs/HANDOFF.md` and `docs/evidence/w01-magic-link-results.json`.
Customer self-provisioning is future scope; this role is internal to Octatrace.

Run local checks with `bash tools/quality_gate.sh` (macOS, pinned SDK).

Device type and selectable/copy-icon identity/status fields are documented in
[W01_DEVICE_COPY.md](docs/W01_DEVICE_COPY.md). Native clipboard acceptance Passed by user confirmation.

Shared parts and separate New device / Existing device flows are implemented and
reviewed in the native app. See [W01_ENTRY_AND_PARTS.md](docs/W01_ENTRY_AND_PARTS.md)
for exact operator steps, Dart walkthrough and test/preview limits. No database
migration is required. CORE provisioning/repeat/update are qualified; the new-board preparation flow retains its separate Pending acceptance.
