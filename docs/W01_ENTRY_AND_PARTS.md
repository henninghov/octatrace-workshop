# W01-U01 — Shared parts and separate device entry

28 October 2026. The requested UI slice is implemented in the Workshop repository
on `feature/W01-provisioning-foundation`, based on published `044c9e2`, with local
uncommitted changes. Shared decisions remain in the mobile app repository.

## Operator steps

**Reuse a part**

1. Open Articles → New article or New revision.
2. Choose existing part. Search by number or description, then select the part.
3. Set its quantity for this revision. Number and description stay fixed.
4. Use Create part for a different component and supply its new number/description.
5. Save revision when the complete definition is ready. Cancel saves nothing.

**New device**

1. Open Devices → New device, or Provisioning → New device.
2. Choose Article and revision, then Device class.
3. Select Reserve device identity once. This creates the registry identity only.
4. After the confirmed registry refresh, Workshop opens the exact returned device
   record under Existing device. Continue the supported provisioning flow there.

**Existing device**

1. Open its registry card, or Provisioning → Existing device → Registry device.
2. Continue verification/update using the existing UUID/serial and evidence.
3. Do not create another reservation for the same physical unit.

New device contains no existing-record selector. Existing device contains no
reservation form. Navigation and choosing parts do not save or provision anything.
Physical USB provisioning remains restricted to unclaimed development LINK devices;
CORE eligibility/firmware/server support is a separate follow-up.

## Dart walkthrough

[`editArticle`](../lib/ui/workshop_app.dart) supplies all loaded article-revision
parts to [`ArticleEditor`](../lib/ui/article_editor.dart). Every current part is
created with an article revision by the existing atomic backend API. The editor
deduplicates by part number and sorts the shared catalogue. There is no new parts
endpoint, schema or migration. The existing backend still enforces uniqueness,
unchanged part descriptions and immutable sealed compositions.

`choosePart` opens the searchable `_PartPicker`. Already-selected shared parts are
disabled to prevent duplicate rows. A selection fills a blank row or a matching
typed draft; otherwise it adds a row without discarding other inputs. Selecting a
matching typed number restores its canonical description and preserves quantity.
Only the draft row changes. Shared number/description inputs are read-only;
quantity remains editable. Typed attempts to create an existing number receive
inline guidance to use the chooser. The existing duplicate and quantity validators
still run before `save` returns the normal `ArticleDraft` JSON.

Each `_PartInputs` owns its editing controllers. Picker results are ignored after
the parent is disposed, and removed row controllers are disposed after unmount.
New revisions copy values into independent controllers, so draft edits never mutate
the source revision or another article's quantities.

[`WorkshopShell.provisioning`](../lib/ui/workshop_app.dart) uses `creatingDevice`
to render the two separate paths with the existing visual components/assets.
Opening a registry card selects Existing device directly; New device from Devices
clears the previous identity/revision and starts in development class D. Busy
operations disable switching; existing cancel/logout/evidence behavior is retained.

`reserveDevice` calls [`WorkshopController.reserve`](../lib/domain/workshop_controller.dart).
The gateway now returns the UUID already supplied by the existing
`workshop_reserve_device` RPC rather than discarding it. The controller retains
the durable request ID, awaits the registry refresh/acknowledgement, and returns
that UUID only for the unchanged successful account session. The UI opens only
the matching registry record, revision and serial class. It does not guess the
device from list order or newly appearing rows, so retries can open an identity
already loaded during an earlier refresh. Failed/late operations keep the
existing recovery behavior and never open another account's record.

## Validation and limits

126 Flutter tests plus configured startup pass. Fatal-info analysis, format and
the configured macOS debug build pass. Measured Dart coverage is 1,432/1,432
executable lines, including critical domain/auth/storage/process sources; branch
coverage is unmeasured. Seven new behavior cases verify separate entry, exact-ID
reservation response/retry, empty registry, search/cancel, canonical part reuse,
independent quantities and typed-existing-number recovery. Existing diagnostic,
account, cancellation and evidence tests still pass. Ten visual checks pass with
reviewed light/dark renders; a settled extra frame avoids incomplete initial text
painting in captures. No screenshot tolerance or skipped check is introduced.

The configured build is reopened from its owning repository. The user signs in
with a fresh magic link. Native review observes separate creation/selection paths,
the original provisioned LINK, one chooser entry per shared part across revisions,
search, selected read-only identity fields, editable draft quantity and Create part.
The draft is cancelled and the original quantities remain unchanged. Workshop is
left signed in on Devices. No agent reservation, article save, USB write or flash
is performed during this review. Cloud mutation semantics remain covered by the
existing gateway/backend checks; this slice creates no real inventory for testing.

The editable local prototype is updated with the same choices, shared parts and
immutable revision drafts; its actions remain simulated. All three inline scripts
pass static syntax checks. Browser runtime review was not run: browser policy
blocked the local file URL. No alternate browser/server workaround was used, and
no prototype runtime pass is claimed. The native Flutter UI is reviewed separately.

[Source/build receipt](evidence/w01-entry-parts-results-20261028.json).
Full W01, CORE provisioning, release management and the earlier untraced Bluetooth
retry observation/HS01 are not marked complete by this UI pass. No deployment,
migration, commit, push or merge is performed.
