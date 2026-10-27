# Octatrace Workshop

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

The firmware-owned Python CLI is invoked directly with its existing role/build
checks and USB contract. Its current identity response is unprovisioned/null.
Permanent identity installation and physical provisioning completion require the
next firmware contract; the app keeps these actions disabled. Reserving a record
and receiving diagnostics never mark the physical unit provisioned.

The existing clickable prototype is retained in `design/Octatrace Workshop.html`,
with editable source in `design/prototype.html`. New flows are explicitly simulated.
They extend the user's existing Workshop design rather than replace it.

Shared product/security/quality decisions remain in the mobile app repository.
Read `docs/W01_FOUNDATION.md` for the code walkthrough, backend setup and limits.
Local host checks pass: 73 tests + configured startup, 949/949 measured executable
Dart lines and macOS debug build. W01 remains in progress for metadata mutation
idempotency and physical provisioning. See `docs/HANDOFF.md` and `docs/evidence/w01-magic-link-results.json`.
Customer self-provisioning is future scope; this role is internal to Octatrace.

Run local checks with `bash tools/quality_gate.sh` (macOS, pinned SDK).

Device type and selectable/copy-icon identity/status fields are documented in
[W01_DEVICE_COPY.md](docs/W01_DEVICE_COPY.md). Native clipboard acceptance Passed by user confirmation.
