# Firmware host regression tests in Workshop

These controls run existing firmware-owned software tests on the Mac. They do
not operate a board or establish physical-device acceptance. The tooling suite
runs the firmware's discovered Python regression cases; the native host suite
runs its existing contract, simulator, sanitizer and coverage gates for LINK
and CORE. The same controls also offer seven standalone contract qualifications:
authority storage, claim QR, device authority, device credential, field
handshake metadata, proof context and setup transfer, plus the native session
control qualification with its nine negative controls. Authority and field
resource qualifications use the current role builds and checked compiler inputs;
the field resource run first repeats the native host prerequisite. Authority
layout also uses the verified historical baseline, measures the current tooling
tests and makes a separate LINK build for coverage. Other firmware
qualifications and device procedures are not yet all available here.

## Set up a machine

Use a local firmware checkout, the Workshop's pinned Flutter/Dart SDK, macOS
with Xcode tools, Node.js and the firmware's pinned native build dependencies.
The latest local environment check used Python 3.9.6 and Node 20.19.1. Follow
the firmware checkout's `tools/README.md` for `bootstrap.py`,
`bootstrap_assets.py`, the pinned toolchain and the licensed Excon fonts.
The firmware bootstrap also prepares and verifies the two field-handshake
archives needed by the host suite; it can use an explicit offline archive seed.
Do not copy a Python virtual environment from another machine.

For the host tests, create a Python environment on the current machine. In the
following example, set `FIRMWARE_ROOT` to the actual firmware checkout path:

```sh
python3 -m venv "$FIRMWARE_ROOT/build/test-venv"
"$FIRMWARE_ROOT/build/test-venv/bin/python" -m pip install -r "$FIRMWARE_ROOT/requirements-claim-qr.txt"
"$FIRMWARE_ROOT/build/test-venv/bin/python" -m pip install --require-hashes -r "$FIRMWARE_ROOT/requirements-bench.txt"
```

The schema requirement file pins package versions; the USB transport file also
pins its package hash. Some native checks require additional source-bound SDK
archives, Xcode compiler tools and fonts. A missing dependency is a failed or
unavailable run, not a pass. This setup has been checked in a fresh Python
environment on the existing Mac; full acceptance on a new machine is open.

Before the native host suite, build the current firmware source for both roles
using the same checkout and licensed font directory. The native checks use the
LINK build's generated compiler commands; a fresh checkout does not contain
them. Set `FONT_DIR` to the licensed fonts and run:

```sh
"$FIRMWARE_ROOT/build/test-venv/bin/python" -B "$FIRMWARE_ROOT/tools/build_firmware.py" --role Link --font-dir "$FONT_DIR"
"$FIRMWARE_ROOT/build/test-venv/bin/python" -B "$FIRMWARE_ROOT/tools/build_firmware.py" --role Core --font-dir "$FONT_DIR"
```

These commands compile locally; they do not flash a device. Do not use build
outputs from an untrusted checkout or another source revision.
The authority-layout check also needs both current role builds, the licensed
fonts and sufficient time and disk space for an additional isolated LINK build.

## Run and export

1. Sign in to Workshop and open **Test bench**. Expand **Firmware host regression
   tests**.
2. Enter the firmware checkout folder and the absolute path to the test
   environment's Python executable and the licensed firmware font directory.
   Both suites render firmware artwork and require those fonts.
3. Select a regression suite or standalone qualification and select **Run
   firmware tests**. The status remains running until the owner
   runner and its saved evidence have been checked. Cancel requests termination;
   failures and interrupted attempts remain available.
4. Select **Reopen reports** to choose a saved attempt. The displayed suite,
   status, attempt, operator, firmware source and Workshop bundle fingerprint
   identify the result. To export it, enter an
   existing folder and select **Export selected report**. The export contains
   the report and supporting host evidence; treat it as private.

The reviewed adapter accepts only the fixed suites listed in its versioned
definition, verifies owner-runner pins, checks baseline case IDs and source
stability, and saves the attempt before running tests. The app checks the saved
source inventory and the owner report before displaying a pass. Version 1 host
reports remain readable. A fresh firmware source changes the reported
fingerprint; it does not change the source binding of earlier device guides or
reports.
When an owner-runner pin or reviewed definition changes, publish a new immutable
definition revision and retain the prior adapter/definition reader and report
bindings; do not replace the meaning of an older attempt.
