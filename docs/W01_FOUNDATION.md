# W01 — Workshop foundation

The macOS app signs an existing Octatrace user in with a magic link, checks an internal operator
role, and exposes articles, device identity reservation and shared USB diagnostics.
The same Supabase UUID can use the mobile app and Workshop. Workshop authority is
separate from device ownership. Customer self-provisioning and organization-scoped
roles are future work; do not grant this internal role to customer operators.

`provisioning.devices` holds physical hardware identities. A row has a permanent
UUID, D/R/O + 12-digit serial, article and exact immutable article revision.
Reservations are unclaimed. Mobile onboarding will claim an existing device;
Workshop never assigns its owner.

## How the code works

1. `lib/main.dart` reads public backend configuration and the firmware checkout
   path. Missing configuration opens a disabled login with setup guidance.
   `lib/ui/workshop_app.dart` draws the supplied prototype's branding and layouts.
   Runtime screens contain backend records; synthetic examples live in tests and
   the explicitly simulated HTML prototype.
2. `WorkshopController.requestLink` validates the email and asks
   `SupabaseGateway.requestLink` to send an existing-account magic link, with
   `shouldCreateUser: false`. `MemoryPkce` keeps a random proof in this process.
   No password is requested. A sent email does not open the registry.
3. `nativeMagicLinks` forwards macOS URL events. `WorkshopController.acceptLink`
   accepts only Workshop's exact callback, one code and an active local request.
   A callback arriving during mail delivery waits for that request to settle.
   The SDK exchanges the code with its PKCE proof; the server-verified email must
   match the request. Only then do operator authorization and registry load run.
   `SupabaseGateway._rpc` binds each request to the initiating token and the SQL
   rechecks the enabled operator. A verified session alone grants no Workshop
   access. Wrong/expired/duplicate/cancelled/cold-start links cannot bypass this.
4. `ArticleEditor` in `lib/ui/article_editor.dart` owns its form controllers for
   the dialog's whole lifetime, including its closing animation. Each part has separate number, description and quantity inputs, with Add part/
   remove controls. Inline validation retains the draft and scrolls to its first
   invalid field. Saving creates an article/revision with the same typed parts list. A later revision preserves the earlier
   case/BOM; old devices keep their selected revision.
5. `WorkshopController.reserve` writes a retry UUID locally before its RPC.
   `EvidenceJournal` in `lib/services/evidence_journal.dart` keeps that UUID through
   a lost response or failed refresh. SQL locks the request and allocates from one
   non-cycling global sequence. D, R and O and both hardware roles share it. Only a
   confirmed refreshed registry clears the reservation request.
6. `ProcessBenchRunner` in `lib/services/bench_runner.dart` verifies the pinned
   firmware USB contract bytes, validates role/build/port, then invokes the existing
   Python CLI directly. Python owns USB framing, schemas, deadlines and assertions.
   The Dart wrapper bounds process time/output and can cancel its owned child.
7. `WorkshopController.verify` saves each diagnostic privately before upload.
   Failed/cancelled attempts remain diagnostics. Pending evidence survives logout;
   retry keeps its ID. The server rejects conflicting reuse of an evidence ID.
   Evidence folders are separated by backend origin and account, under
   `~/Library/Application Support/com.octatrace.workshop/evidence/`.
8. Sign-out closes the UI immediately. Generation checks invalidate late work,
   and a pending mail request or code exchange must settle before its SDK session is cleared. New login
   waits for logout cleanup. A late USB result remains in its original account's
   local journal and cannot restore a signed-out screen. Disposal retains an
   awaitable `closed` future for asynchronous process/SDK cleanup.

Dart's `Future` represents work that finishes later. Every `await` is a point where
logout can happen, so an operation checks its captured generation before later
side effects. An interface describes the operations a controller needs; tests use
controlled implementations while runtime supplies real SDK, file and process
adapters. The business controller has no Supabase or subprocess dependency.

## Database ownership

The single migration history remains in the mobile app repository:
`../vectrc-app/supabase/migrations/20261026180000_workshop_registry.sql`.
The following `20261027160000_article_revision_device_identity.sql` migration
removes the redundant hardware field; article revision defines the complete build.
See [first reservation walkthrough](W01_RESERVATION.md).
Private `provisioning` tables have RLS and no customer/desktop direct grants.
Checked public RPCs expose only the internal operator workflow. SQL and real
concurrent-connection tests live beside that migration, with synthetic users.

Only one designated registry may issue physical serials. Cloned development/test
backends must not independently allocate serials for real devices. The disposable
SQL acceptance database uses synthetic rows and never provisions hardware.

## What is deliberately unfinished

The existing USB identity contract reports unprovisioned/null identity. It cannot
write permanent UUID/serial/key material. `Install and provision` remains disabled;
a reservation or passing diagnostic never marks a unit provisioned. Complete the
coordinated F01 writer/readback/reboot/rollback contract and decide key storage
before installing identities. Ownership proof and app claiming are later work.

Article creation is protected by unique article codes, but revision creation does
not yet have a durable client request ID. After an uncertain save, refresh and
inspect the revision list before trying again. Add idempotent article/revision
mutation requests before production use. There is no offline serial allocation.

The app is an internal, non-sandboxed build using local Python tools. Distribution,
installer/signing/notarization and multi-Mac packaging remain future work. The hosted migration and approved internal operator grant are now verified.
Local tests do not establish real email sign-in, physical USB results, identity
write or firmware installation; their acceptance is recorded separately.

## Operator setup and first sign-in

1. The approved development migration is applied and the selected existing account
   is enabled in `provisioning.operators`. Users cannot grant this role themselves.
2. The Workshop callback is registered while all previous callback URLs and the
   Auth site URL are preserved: `com.octatrace.workshop://login-callback`.
3. Copy `config/development.example.json` to `config/development.local.json`.
   Use only the backend URL, publishable key and firmware checkout path.
4. Prepare the firmware-owned Python environment using that repository's bench
   instructions. Keep its contract at the consumer pin; do not bypass mismatch.
5. Run Flutter macOS with `--dart-define-from-file=config/development.local.json`.
6. Enter the approved account email and choose Send sign-in link. Keep Workshop
   open, open the newest email on this Mac and click its link. Confirm Devices
   opens. Cancel sign-in invalidates the pending local request. Closing the app
   clears its memory-only verifier/session; request a new link after restart.
   Create the first article/revision only with a reviewed case/parts definition.
   Reserve physical identities only against the authoritative serial allocator.
7. Run USB diagnostics with the exact role/source hash and verify real evidence
   separately. This foundation does not complete physical provisioning.

See `docs/HANDOFF.md` for measured verification and remaining acceptance.

## Magic-link verification

The final suite covers email validation/provider failure, PKCE request shape,
existing-account-only delivery, unconfirmed/wrong identities, invalid/duplicate
callback parameters, delayed mail responses, expired codes, cancellation/logout,
platform stream errors, denied/revoked operators and all existing registry/USB
flows. It passes 54 tests plus configured startup and 853/853 Dart lines, with
branch coverage unmeasured. The user also passes the real email click/return on the configured macOS build;
Devices opens and the signed-in workspace was independently observed. No inventory
content has been added. This remains separate from physical device provisioning.
[Supabase PKCE/passwordless reference](https://supabase.com/docs/guides/auth/auth-email-passwordless).
