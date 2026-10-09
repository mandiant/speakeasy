# Supplied regression patch comparison

The supplied patch was compared against PR #348 at `bc7e964`, then exercised through independent PE fixtures and public load/run calls. Its intended fixes were already implemented, but the direct integration repros found two gaps that the earlier parser-only tests did not expose. Those gaps are fixed rather than excluded from the tests.

## Behavior and coverage map

| Supplied change or repro | PR behavior and coverage |
| --- | --- |
| Legacy `get_symbols()` dictionary | Registry-backed tuple snapshots plus auxiliary symbols. `test_symbol_compatibility.py` covers mapped/dynamic/data/native exports, snapshot isolation, private-token exclusion, forwarders and kernel labels. The new public IAT test also checks its bound address. |
| Per-run timeout accounting | Typed `Run.execution_elapsed`; `finally` charges the captured origin run. Existing public clock tests and new native PE/IAT calls exceed a session's budget across five independent successful runs. `test_run_boundary_regressions.py` checks queued replacement and the successor's zero initial budget. |
| Per-DLL signature index | Built once in source loading, preserving architecture, declaration order, source precedence and lazy signature conversion. `test_export_catalog.py` checks operation counts and declaration identity. |
| NX recovery inside guest modules | Deferred page execute promotion after Unicorn unwinds, preserving R/W bits. Public `run_module()` tests cover x86/x64, NXCOMPAT on/off, default/recover/enforce policy and adjacent-page permissions. Existing tests cover instruction boundaries, recovery failure ownership and debugger/API-image protection. |
| Unknown Win64 fallback | Scalar return 1 only for wholly undeclared APIs with the flag enabled. Public PE calls verify that the next IAT call executes; x86 and disabled fallback stop with `unsupported_api`. Catalogued float/aggregate declarations remain unsupported on both architectures. |
| SP-changing hook guard | One `api_handler_did_not_return` error, including the API name. Direct IAT tests reproduce the supplied stack push. Existing tests cover handled and hook-only APIs; new positive tests cover completion, run replacement and actual deferred guest callbacks. |
| Malformed delay directory and attributes | Warn/drop optional delay inventory by default; strict parsing rejects it. Direct PE execution still reaches GetTickCount. Policy tests cover partial parsed inventories and preserve raw guest bytes. |
| Invalid IAT slots and missing function names | Warn/skip invalid entries in lenient mode, reject in strict mode. Added tests cover static/delay zero, outside-image and tail slots, missing/empty names and non-ASCII names. |
| Invalid export directory, target or forwarder | Preserve the image and valid sibling entries in lenient mode. Strict mode rejects. Existing and new tests cover bounds, truncation, empty/bad/overflow forwarded ordinals and missing terminators. |
| Non-ASCII imported DLL | Retain Latin-1 bytes and original module identity. Public load/run tests now cover the supplied unused-import case and calls to two distinct non-ASCII modules, including symbols, IAT addresses and loader-list membership. Strict parsing rejects these names. |
| PMA timeout allowances removed | The 01-02 and 05-01 assertions remain restored. No test budget or error allowance is widened for this comparison. |

## Intentional differences

The supplied timeout loop assumes roughly 96 million iterations finish below one second on every runner. The PR uses a local deterministic execution clock with actual guest instructions and API yields instead; this reproduces budget starvation without making CPU speed an assertion.

The supplied NX change returns success without changing the guest page's protection. That approach previously replayed protected fetches during PMA18-03 unpacking. The PR promotes the page outside native callbacks and tests that there is one protected-fetch recovery rather than repeated faults.

The supplied x64 fallback tests only whether an emulatable signature is absent. A known but unsupported float/aggregate declaration also meets that condition. The PR checks exact declaration presence separately, so it does not turn a known incompatible ABI into a guessed integer return.

The supplied SP guard rejects an unchanged PC even when a handler scheduled a continuation. The PR additionally considers changed SP, pending controls, callback ownership, run replacement and completion. Positive continuation tests prevent a guard fix from suppressing legitimate transfers. The error spelling remains `api_handler_did_not_return`; the supplied `api_handler_no_return` describes the same failure.

Registry ownership wins over stale auxiliary labels at the same public address. The supplied symbol shim uses `setdefault`, which would preserve the stale label. Independent auxiliary symbols still resolve.

Non-ASCII DLL descriptors are preserved rather than skipped. Non-ASCII function-name metadata is warned/skipped rather than decoded with replacement characters: replacement would invent a different symbol identity. This is a lenient-parser policy for malformed metadata; the [PE hint/name format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#hintname-table) defines case-sensitive ASCII import names.

## Additional confirmed gaps

**Non-ASCII module creation:** the earlier loader accepted a Latin-1 DLL name, but synthetic image construction still required an ASCII module name. Public `load_module()` therefore failed before the valid GetTickCount call ran. The synthetic PE now uses an ASCII export-directory label while `LoadedImage.name`, the emulated path, registry labels and loader lists retain the original module identity. Two different such filenames remain distinct modules and callable imports.

**Filtered import slots:** pefile can remove malformed named imports from its parsed list. Both the supplied patch and the previous PR computed IAT addresses by enumerating that shorter list, assigning a later valid function to an earlier slot. The loader now inventories raw thunk positions and uses parsed metadata at those positions. Named and ordinal survivors retain their slots, with OriginalFirstThunk present/zero and original/rebased images. A malformed first entry followed by GetTickCount also executes correctly through the public API; the skipped slot's bytes remain unchanged.

The raw inventory is bounded, preserves pefile's accepted symbol boundary, honors its IAT fallback when the preferred name table is unreadable or empty, and rejects reserved thunk bits rather than inventing an ordinal alias. Default warnings and strict rejection apply consistently.

## Validation

The focused loader/image/public execution suite passes 398 tests. This adds 222 parametrized regression cases: 46 public PE/IAT cases, eight run-boundary cases and 168 parser-policy cases. The 37 common PMA cases retain 201 runs and 11,628 recorded API events; the 24 additional PE selections retain 24 runs and 1,522 events, including the same two unsupported managed-image controls. Every per-run API sequence and error type matches the earlier reviewed head. Five fresh-process startup measurements have a median 0.1561s total and 7,887 legacy symbols, versus 0.1552s before these loader fixes; this small timing difference is descriptive, not a performance assertion.

The full GDB-enabled local suite passes **1,976 tests, 14 skipped in 139.63 seconds**; repository lint and diff checks pass. Exact-head CI results and comparison evidence are recorded in the PR description and the Obsidian implementation-status document. The original review response retains the broader corpus findings and remaining fidelity limits. This establishes coverage of the supplied patch's behaviors and identified integration gaps, not exhaustive coverage of all Windows loader semantics.
