# W01-AR01 — structured article parts

27 October 2026. The previous dialog expected `part number | description | quantity`
inside a multiline text field. Its only instruction disappeared when typing, so
ordinary component names produced an unhelpful generic error. The user requests
separate inputs. No supplier/internal part numbers are assigned automatically.

## How to use it

1. Articles → New article. Enter the article code, name, product and case version.
2. Enter the first part number, description and quantity in their own inputs.
3. Choose Add part for each additional component. Use Remove part to remove a row.
   At least one row remains. Review quantities; new rows initially show 1.
4. Choose Save revision. Invalid inputs show errors beside the relevant field;
   entered values stay in place and the dialog scrolls to the first error.
5. After a successful cloud save, check that the article/revision lists the expected
   component numbers and quantities. Do not invent catalogue numbers for real parts.

## Code walkthrough

`lib/ui/article_editor.dart` owns this repair. `_PartInputs` holds three editing
controllers per row. `initState` creates new row controllers, or copies an existing
immutable revision into independent editable rows. Changing the form cannot change
that stored revision. Each row has a stable local key, so removing one does not
move another component's values into the wrong inputs.

`_partRow` renders the three inputs beside each other on desktop and stacks them
at narrow widths. Its validators check required values, database length limits,
whole-number quantities from 1 to 1000000 and repeated part numbers. The operator
can combine a repeated part into one row with its total quantity.

`save` validates the form before returning an `ArticleDraft`. Invalid fields keep
all their values; valid rows become the existing JSON objects with `part_number`,
`description` and integer `quantity`. The existing gateway and Supabase functions
remain unchanged. A description may contain a pipe character because it is now
ordinary text rather than a delimiter.

`_remove` updates the row list, then disposes removed controllers after their
widgets unmount. The dialog's remaining controllers live through its closing
animation and are disposed with the dialog state. This avoids the earlier class
of controller-lifetime failure.

## Evidence and limits

The old editor first fails the new regression. Final host checks pass 60 Flutter
tests plus configured startup, 910/910 executable Dart lines, formatting,
fatal-info analysis and a configured macOS debug build. A dark dialog render was
visually inspected with synthetic examples. Tests cover a real three-part typed
save, invalid quantities, missing/long fields, duplicate parts, safe removal,
revision prefill, narrow layout and existing authentication/registry flows.
No branch percentage is claimed. See `evidence/w01-article-input-results.json`.

Native retry Passed: the user signs in, completes the new form and provides a
screenshot of the saved first article. A read-only hosted check confirms its four
parts and quantities. Draft restoration is superseded by that successful save;
no duplicate article is created by the agent. Screenshot draft
values are preserved privately under the app repository's ignored build directory;
no real inventory, sample catalogue IDs or private draft data enter Git. This pass
changes no schema, auth boundary, device identity or firmware. Article/revision
mutation request idempotency remains a separate pending item.
