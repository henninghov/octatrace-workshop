# Workshop context

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
