# Supplied regression patch comparison

The supplied patch was compared against PR #348 at `bc7e964`, then exercised through independent PE fixtures and public load/run calls. Its intended fixes were already implemented, but the direct integration repros found two gaps that the earlier parser-only tests did not expose. Those gaps are fixed rather than excluded from the tests.

## Behavior and coverage map

| Supplied change or repro | PR behavior and coverage |
| --- | --- |
| Legacy `get_symbols()` dictionary | Registry-backed tuple snapshots plus auxiliary symbols. `test_symbol_compatibility.py` covers mapped/dynamic/data/native exports, snapshot isolation, private-token exclusion and kernel labels. The public non-ASCII import test also checks the symbols of its import targets. |
| Per-run timeout accounting | Typed `Run.execution_elapsed`; `finally` charges the captured origin run. A public PE/IAT test runs `run_module()` and `call()` whose combined time exceeds the per-run timeout; both runs complete without error. `test_run_boundaries.py` checks that a queued successor run owns its own API events. |
| Per-DLL signature index | Built once in source loading, preserving architecture, declaration order, source precedence and lazy signature conversion. `test_export_catalog.py` checks architecture selection, source precedence and declaration identity. |
| NX recovery inside guest modules | Deferred page execute promotion after Unicorn unwinds, preserving R/W bits. Public `run_module()` tests cover default/enforce policy on an x86 NXCOMPAT image and adjacent-page permissions. `test_run_boundaries.py` covers anonymous-page recovery and API-image protection that fails only its own run. |
| Unknown Win64 fallback | Scalar return 1 only for wholly undeclared APIs with the flag enabled. Public PE calls verify that the next IAT call executes; x86 and disabled fallback stop with `unsupported_api`. Catalogued float/aggregate declarations remain unsupported; a public x64 PE test checks this. |
| SP-changing hook guard | One `api_handler_did_not_return` error, including the API name. A direct IAT test reproduces the supplied stack push. Positive tests cover an SP-changing exit hook that completes its run before a queued successor, and nested guest callbacks from API handlers. |
| Malformed delay directory and attributes | Warn/drop optional delay inventory by default; strict parsing rejects it. Direct PE execution still reaches GetTickCount. Policy tests apply the default and strict outcomes to user, kernel and dependency loads; a loader test checks that valid delay IAT bytes stay unchanged in the mapped image. |
| Invalid IAT slots and missing function names | Warn/skip invalid entries in lenient mode, reject in strict mode. Tests cover a non-ASCII function name with OriginalFirstThunk present or zero, reserved ordinal bits and an unreadable lookup table. |
| Invalid export directory, target or forwarder | Preserve the image and valid sibling entries in lenient mode. Strict mode rejects. Tests cover an export target outside the image and a malformed forwarder beside a valid export. |
| Non-ASCII imported DLL | Retain Latin-1 bytes and original module identity. A public load/run test covers calls to two distinct non-ASCII modules, including symbols, distinct entry addresses and loader-list membership. Strict parsing rejects these names. |
| PMA timeout allowances removed | The 01-02 and 05-01 assertions remain restored. No test budget or error allowance is widened for this comparison. |

## Intentional differences

The supplied timeout loop assumes roughly 96 million iterations finish below one second on every runner. The PR's test instead sleeps in an API hook so that two runs together exceed one run's timeout; this reproduces budget starvation without making CPU speed an assertion.

The supplied NX change returns success without changing the guest page's protection. That approach previously replayed protected fetches during PMA18-03 unpacking. The PR promotes the page outside native callbacks, and the `pma-18-03-ocl` case reaches the unpacked network payload.

The supplied x64 fallback tests only whether an emulatable signature is absent. A known but unsupported float/aggregate declaration also meets that condition. The PR checks exact declaration presence separately, so it does not turn a known incompatible ABI into a guessed integer return.

The supplied SP guard rejects an unchanged PC even when a handler scheduled a continuation. The PR additionally considers changed SP, pending controls, callback ownership, run replacement and completion. Positive continuation tests prevent a guard fix from suppressing legitimate transfers. The error spelling remains `api_handler_did_not_return`; the supplied `api_handler_no_return` describes the same failure.

Registry ownership wins over stale auxiliary labels at the same public address. The supplied symbol shim uses `setdefault`, which would preserve the stale label. Independent auxiliary symbols still resolve.

Non-ASCII DLL descriptors are preserved rather than skipped. Non-ASCII function-name metadata is warned/skipped rather than decoded with replacement characters: replacement would invent a different symbol identity. This is a lenient-parser policy for malformed metadata; the [PE hint/name format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#hintname-table) defines case-sensitive ASCII import names.

## Additional confirmed gaps

**Non-ASCII module creation:** the earlier loader accepted a Latin-1 DLL name, but synthetic image construction still required an ASCII module name. Public `load_module()` therefore failed before the valid GetTickCount call ran. The synthetic PE now uses an ASCII export-directory label while `LoadedImage.name`, the emulated path, registry labels and loader lists retain the original module identity. Two different such filenames remain distinct modules and callable imports.

**Filtered import slots:** pefile can remove malformed named imports from its parsed list. Both the supplied patch and the previous PR computed IAT addresses by enumerating that shorter list, assigning a later valid function to an earlier slot. The loader now inventories raw thunk positions and uses parsed metadata at those positions. Named and ordinal survivors retain their slots. Tests cover named survivors with OriginalFirstThunk present and zero, and an unreadable lookup table in a rebased image. A malformed first entry followed by GetTickCount also executes correctly through the public API; the skipped slot's bytes remain unchanged.

The raw inventory is bounded, preserves pefile's accepted symbol boundary, honors its IAT fallback when the preferred name table is unreadable or empty, and rejects reserved thunk bits rather than inventing an ordinal alias. Default warnings and strict rejection apply consistently.

## Validation

The 37 common PMA cases retain 201 runs and 11,628 recorded API events; the 24 additional PE selections retain 24 runs and 1,522 events, including the same two unsupported managed-image controls. Every per-run API sequence and error type matches the earlier reviewed head. Five fresh-process startup measurements have a median 0.1561s total and 7,887 legacy symbols, versus 0.1552s before these loader fixes; this small timing difference is descriptive, not a performance assertion.

The full GDB-enabled local suite passes **1,548 tests, 14 skipped in 14.7 seconds**; repository lint and diff checks pass. Exact-head CI results and comparison evidence are recorded in the PR description. The original review response retains the broader corpus findings and remaining fidelity limits. This establishes coverage of the supplied patch's behaviors and identified integration gaps, not exhaustive coverage of all Windows loader semantics.
