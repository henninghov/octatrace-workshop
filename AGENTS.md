# Octatrace Workshop

At session start read ../vectrc-app/AGENTS.md, ../vectrc-app/docs/CURRENT_STATE.md
and ../vectrc-app/docs/CODEX_WORKFLOW.md, then the active checkpoint's relevant
Workshop plan/source/contracts and quality rules. Local README, context, tasks
and handoff retain historical references; read relevant sections rather than
loading full histories.
Shared product, firmware, identity and quality requirements are canonical in the
mobile app repository (`../vectrc-app` on the original workstation). Link to
those documents; do not create a competing editable shared decision history.

W01 Workshop support has one active feature. Read the current checkpoint and
next eligible step in ../vectrc-app/docs/CURRENT_STATE.md.
Shared scope/acceptance: ../vectrc-app/docs/A07_WORKSHOP_BENCH_PLAN.md.
Definitions include immutable published revision, prerequisites, numbered tester
steps, expected outcomes and evidence; run attempts retain exact definition/build
identity and are separate from provisioning confirmation. Save evidence locally
before optional sync, preserve failed/interrupted attempts and link retries.
Keep intermediate evidence in Git; sync Notion at parent-task closure or a
significant accepted Roadmap decision/blocker.
Keep domain behavior independent of SDK/process/storage adapters. Reuse the
firmware-owned Python test registry and commands; never rewrite assertions in Dart.
Preserve test IDs, limits, provenance and real-vs-simulated evidence boundaries.
Use the existing Workshop clickable design and original logos/fonts. Preserve
unrelated changes and evidence. Never store credentials, device private keys or
real inventory in Git. No false physical passes or silent loss of pending evidence.

Full quality and physical acceptance remain required before marking W01 complete.
No deployment, publication or flashing is authorized by these bootstrap rules.
