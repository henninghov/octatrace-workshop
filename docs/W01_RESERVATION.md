# First LINK identity reservation

27 October 2026. W01-R01 is the registry-only milestone. Physical identity writing
and cryptographic authentication remain separate F01 work.

## What changed and why

The operator selects an article revision and D/R/O device class. There is no
independent hardware revision: the selected immutable article revision already
pins the complete enclosure, components and quantities. Manufacturer PCB versions
belong in component descriptions. Repairs are separate service history.

The device gets a permanent UUID and one globally allocated serial. Reuse this
record for the first LINK's subsequent verification and installation attempts.
A reservation remains **Reserved / Unclaimed**; it does not program the unit.

## Code walkthrough

1. [`provisioning()`](../lib/ui/workshop_app.dart) offers article/revision and device
   class. The button becomes available when an article is selected.
2. [`WorkshopController.reserve()`](../lib/domain/workshop_controller.dart) combines revision/class
   into the durable retry key. `EvidenceJournal.reservation()` saves a request ID
   before the network call; network/refresh failure retains it for a safe retry.
3. [`SupabaseGateway.reserve()`](../lib/services/supabase_gateway.dart) sends only request ID,
   article revision ID and serial class to the server. It has no hardware field.
4. Shared migration `20261027160000_article_revision_device_identity.sql` removes
   the redundant column and old four-argument RPC. The three-argument RPC checks
   the operator, locks that request, reuses an existing matching reservation or
   allocates one UUID/serial and immutable reservation event. Different retry
   parameters fail; one serial sequence serves every prefix and product.
5. A refreshed overview supplies the device's original article revision. Only a
   successful refresh acknowledges the local request. Later checks select the
   existing device from Devices; clicking Reserve again after success creates a
   different physical unit's identity.

The migration takes a table lock and refuses a populated legacy device registry.
This avoids discarding existing metadata. The deployed original migration remains
unchanged. Upgrade requires an empty registry and no pending legacy reservation
journals; a populated installation needs its own preservation migration.

## Exact native acceptance steps

1. Sign in with a fresh magic link after reopening Workshop.
2. Open Provisioning. Confirm only Article and revision and Device class inputs.
3. Select the intended existing LINK article revision and D — Development.
4. Click Reserve device identity once. Wait for the registry refresh.
5. Open Devices. Confirm one device, its UUID/serial, Reserved and Unclaimed.
6. Open that device. Confirm it retains the chosen article revision and that
   physical installation is unavailable. No USB operation is required.
7. Refresh the registry. Confirm the same one identity and one reservation event.
   Do not reserve a second identity for the same unit.

Native/hosted acceptance Passed: operator-selected revision 2, one Reserved /
Unclaimed identity and reservation event, unchanged by a registry Refresh. Device
identifiers remain private. No USB programming occurred.

## Verification and limits

The regression first failed on the old Hardware revision input. The new UI and
exact three-field RPC body pass, along with durable retries/account isolation.
Full gate: 61 Flutter tests plus configured startup; 902/902 executable Dart lines,
critical domain/adapters 100%; format and fatal-info analysis pass. Disposable SQL
suite passes 55 Workshop assertions, populated-upgrade refusal and six Workshop
concurrency races, plus all existing app suites/races. Prototype: 26 existing and
11 foundation checks, all simulated. Configured native build, hosted migration/history/permissions and native
reservation/Refresh acceptance pass; see the evidence receipt. Branch coverage is unmeasured.

One shared firmware image plus separately persistent identity is agreed. Proposed
future security uses a per-device private key with registered public key and
fresh challenge-response. Serial/UUID are identifiers; copying them must never
prove ownership or authorize access. No keys, firmware, flash protections or
physical identity are changed by this milestone. Exact key/storage/recovery
choices await the writer design.
