# Unified API validation and compatibility

This document records the behavioral contracts and validation of [PR #348](https://github.com/mandiant/speakeasy/pull/348). The mapped-entry design remains: EAT, IAT, runtime resolvers and symbols share one registry; public code executes before private trap dispatch. The review correctly identified regressions in the surrounding runtime. In particular, accepting timeout errors in the previous PMA expectation update hid a session-wide timeout defect. Those allowances are reverted.

The subsequent [supplied-patch comparison](unified-api-patch-comparison.md) maps every hunk and reproduction to coverage. Its public PE/IAT tests found and fixed non-ASCII synthetic module creation and filtered-import slot compression; loader tests additionally protect IAT fallback and ordinal validation. The repeated corpus comparison preserves every recorded API sequence and error type from the earlier reviewed head.

## Changes

| Finding | Resolution |
| --- | --- |
| Timeout accumulated across a session | Active elapsed time belongs to `Run`. API yields and debugger actions share that run's budget; every fresh run and public `call()` starts at zero. A separate aggregate active-time budget now bounds a public invocation without starving fresh calls. |
| Repeated full-database enumeration | Index raw declarations by physical DLL once during source loading, sorting each name set once and keeping lazy signature conversion, architecture filtering and precedence. |
| Lost legacy symbols | `get_symbols()` returns fresh `{address: (dll, name)}` snapshots from the registry plus auxiliary symbols. Exact kernel auxiliary lookup is restored. |
| Non-X guest sections stopped execution | Ordinary analysis defaults to recovery; `analysis.enforce_nx=true` opts into enforcement. Guest PE page execute permission is granted after native unwinding, preserving other permissions. Debugger faults and synthetic API protection remain authoritative. |
| Malformed optional PE inventories blocked loading | Default lenient parsing warns and omits malformed delay directories, export entries and forwarders; non-ASCII DLL names retain their bytes through Latin-1 decoding. `modules.strict_pe_parsing=true` / `PeLoader(strict=True)` retains strict validation. Mapping, architecture and relocation safety checks remain mandatory. |
| Unknown x64 calls stopped despite permissive configuration | Preserve an argument-opaque scalar-return-1 fallback only for wholly undeclared Win64 functions with `functions_always_exist`. Unknown x86 calls require a known ABI or explicit hook. Known unsupported float/aggregate declarations remain unsupported. |
| SP-changing hooks redispatched | Report `api_handler_did_not_return` once when a handler changes SP without returning or scheduling a transfer. `_EH_prolog` retains its explicit return. |
| Listener exceptions escaped committed loads | Log and isolate each observer; later observers still run after load/discard. |
| Injected import repair stopped halfway | Default validation stages independent valid entries and warns about skipped entries. Strict mode requires all entries to validate. A write fault during commit leaves earlier writes in place; bookkeeping publishes only after all writes succeed. |
| Kernel compatibility stub corrupted PE headers | Allocate `KiSystemCall64` in separate RX storage near the kernel; preserve both relative SSDT references and auxiliary symbols. |
| SEH continuation replayed an unchanged fault | Preserve the existing four-fault guard across handler returns. Reset it only after resumed guest execution advances, the fault key changes, or a fresh run starts. Handler/filter execution alone is not guest progress. |
| Corpus CRT startup writes faulted | Declare `_fmode`, `_commode`, and `__initenv` as writable data exports. Their existing pointer accessors share the same storage. Function entries stay RX. |

The migration guide now records known-module missing-name NULL results, catalog-known DLL loading independent of the unknown-module flag, configured native modules executing their own guest code, removal of loader fallbacks, debugger timeout policy and symbol compatibility. It also records syscall-layout and Nt/Zw alias limits.

## Instruction-count performance

The precision fix uses Unicorn's native count as a ceiling for each invocation, preventing an extra traced instruction at the cap. Exact consumed-count accounting still uses a Python callback when a cap is configured. This performance issue is **not resolved**.

[Unicorn 2.1.4 resets and maintains its consumed counter internally](https://github.com/unicorn-engine/unicorn/blob/2.1.4/uc.c#L987-L1024), without a public consumed-count interface. REP probes produced the same block history and final PC for different precise counts; partial terminal blocks also overcount in a block-only prototype. An approximate counter would silently weaken the limit. A native consumed-count and count-limit-status interface is the appropriate follow-up. Debugger, REP, partial-block, API-yield and exact-boundary tests preserve correctness meanwhile.

## Comparison method

Baseline `351c1d7`, original PR `e38aed3`, and fixed code use separate worktrees; no tree is switched under running tests. Each has pinned Win32JSON/PHNT and capa-testfiles submodules, with signature archives generated by that tree's own scripts. Measurements are serialized on macOS ARM64, Python 3.13.5, Unicorn 2.1.4, with memory tracing disabled unless testing it explicitly. Native guest instructions run only in the emulator.

The comparison covers all 37 existing PMA cases and 24 deterministically selected additional capa PEs: 12 x86 and 12 x64, under 2 MiB on disk and 32 MiB mapped. Two managed images are unsupported controls on every tree; 22 are native PE comparisons. PMA profiles retain their existing budgets. Additional cases use timeout 2 seconds and API limit 200. This is a bounded exploratory corpus, not a statistically representative malware evaluation.

Per-run API-name sequences, run counts, errors and wall times are captured. Event deduplication means report event totals differ from raw API invocation counts. Neither a larger total nor a clean error field establishes deeper payload coverage; changed tails are investigated separately.

Five fresh-process Lab 01-01 measurements on the final code give these medians:

| Tree | Load | Execute | Total | Legacy symbol entries |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 0.0625s | 0.0433s | 0.1060s | 2,658 |
| Original PR | 0.2355s | 0.0168s | 0.2521s | 0 |
| Final fixed PR | 0.1420s | 0.0132s | 0.1552s | 7,887 |

This removes much of the enumeration regression. The broader synthesized catalog and registry still add startup work compared with baseline; no parity claim is made.

The final aggregate captures below use the 37 common PMA cases; the additional `ocl.exe` profile is verified separately. Wall time includes loading and execution. Increased execution under fresh per-run budgets can increase aggregate time even after startup improves.

| Corpus / tree | Runs | Recorded API events | Load exceptions | Total wall time |
| --- | ---: | ---: | ---: | ---: |
| PMA baseline | 192 | 10,196 | 0 | 12.166s |
| PMA original PR | 201 | 12,740 | 0 | 17.756s |
| PMA final | 201 | 11,628 | 0 | 11.266s |
| Additional PE baseline | 24 | 1,558 | 2 managed-image rejections | 9.859s |
| Additional PE original PR | 23 | 1,505 | 2 managed + 1 malformed forwarder | 12.386s |
| Additional PE final | 24 | 1,522 | 2 managed-image rejections | 9.955s |

These totals are descriptive, not pass/fail scores. The comparison captures per-run sequences, errors, selection criteria and timing separately; aggregate totals cannot establish payload coverage. The repository PMA profiles and regression tests provide the repeatable validation cases.

## Behavioral investigations

**PMA18-03:** the original PR faults before recording APIs. Returning success from protected-fetch recovery restores execution but repeatedly faults, timing out during import resolution. Deferred page recovery reduces this to one fault on each of three pages and completes in about 0.08 seconds. Changing permissions inside the native fetch callback crashes the macOS JIT in an isolated probe; production changes are deliberately deferred until native unwinding.

The baseline's `wsprintfA`/`MessageBoxA` tail reports a failed Winsock ordinal 115 lookup, followed by `ExitProcess(115)`. Fixed code resolves the explicit WSAStartup ordinal and reaches the unpacked payload. It intentionally exits with 1 under the corpus filename because the payload requires `ocl.exe`. A controlled filename change exposes DNS, a connection to port 9999, and socket-backed `CreateProcessA("cmd")`. This demonstrates a coverage gain rather than a missing GUI behavior.

**PMA14-02:** fewer events accompany successful API-hammer patches and thread cleanup. Baseline changes the bytes but continues executing translated calls until the API limit; original/fixed reach `free` and `ExitThread`. Preserved prefixes, patched bytes, branch targets and cleanup tails support this interpretation. No single-change ablation separates explicit cache invalidation from outer dispatch.

**PMA05-01:** Linux CI exposed a separate individual-run timeout after the session-wide timeout fix. `continue_seh()` cleared the repeat guard on every handler return, allowing hundreds of identical faults and C++ handler calls. The existing temporary-page cleanup means these faults are not actually repaired. A progress-aware guard now bounds unchanged replay with the existing `invalid_read` policy; it does not pretend the C++ exception was handled. Handler/filter instructions cannot reset the counter, but genuine resumed guest progress can. No PMA budget or allowed-error assertion is relaxed. The refreshed capture completes in 0.387 seconds, with all 12 runs executing and the failing exports recording 92/24 events versus baseline 93/25; differences are at exception boundaries. The public per-run timeout test independently establishes restored lifetime scripting behavior.

**Additional corpus:** a DLL containing malformed forwarders now loads and completes its attach path, with the baseline's 12 recorded events. This proves lenient loading, not successful resolution of those malformed forwarders. The two CRT-global specimens now pass their original protected writes: one restores baseline's 11-event clean completion; the other reaches the baseline graphics tail and stops at an unsupported CRT API.

## Remaining limits

Instruction-cap callback overhead remains a follow-up. Private-reservation data accesses and unallocated fetches now receive typed errors and existing guest SEH dispatch without materializing reservation pages. Default startup initialization failures warn, retain mapped exports with failed state, and continue independent analysis; strict mode terminates startup. Runtime initialization failures roll back new attachments. Continuing analysis does not mark a failed DLL initialized.

The replay guard tracks fault PC and address; same-PC partial instruction progress such as REP and complete temporary recovery-page ownership remain separate SEH work. Some corpus differences still involve exception emulation and event deduplication. In particular, PMA17-02 retains a ServiceMain timeout and a later invalid-read difference from baseline; correcting per-run budgets restores later runs but does not prove full sample equivalence. Kernel-mode export manifests, real syscall layout, complete data declarations, and a larger external malware corpus remain necessary for stronger fidelity claims.

The change remains an integrated PR. Core address ownership, loader publication and dispatch have coupled invariants; parser leniency, CRT globals, SEH replay and signature curation are independently reviewable and could be extracted. Separate PRs have not been created. The PR remains open for review and is not merged.

## Validation

Signature generation and repository lint pass. The local execution with GDB tests enabled passes **1,548 tests, 14 skipped in 14.7 seconds**. An earlier Linux CI head exposed the PMA05-01 individual-run timeout described above; the focused fix keeps its budgets and assertions intact. Exact-head CI results are linked in the PR description. Public tests cover fresh `call()` budgets, Win64 fallback and rejected known ABIs, SP-changing hooks, symbols, guest stores into CRT data, and precise capped execution with tracing enabled/disabled. Live RSP sessions cover breakpoints and stepping on x86 and x64, and patches, watchpoints and hook faults on x86. The PR description links the corresponding CI run.

## Earlier-review coverage audit

The review of `bc7e964` identified additional concerns beyond the supplied-patch regressions. The following contracts supplement the changes above:

| Concern | Contract and regression coverage |
| --- | --- |
| A guest can enqueue successive runs indefinitely | `max_total_time` bounds active execution across a public invocation, independently of per-run `timeout`. Fresh public calls reset it; paused debugger time is excluded. Host hooks are cooperative and can overshoot while blocked. |
| One unresolved import prevents unrelated code from loading | Default static binding warns and preserves independent successful slots, leaving unresolved bytes intact. It never fabricates native exports. Strict mode retains complete validation and graph rollback. |
| One malformed hollowing descriptor prevents every binding | Default injected binding skips independently malformed descriptors/slots and binds valid entries, including entries after a bad middle thunk. Tests cover a bad middle thunk under lenient binding and strict atomic validation, and repeated repair keeps a guest IAT patch. |
| One dependency DllMain failure prevents the sample from running | Default startup records failure without claiming successful attachment, keeps mapped IAT targets alive, and continues independent dependencies and the sample. Strict startup remains terminal. Runtime `LoadLibrary` continues to return failure and roll back new attachments. |
| Hook detectors reading private jump targets bypass guest SEH | Native execution yields before exception delivery. Guest x86 SEH can redirect the context; unchanged read/write replay remains bounded. x86/x64 unhandled probes produce typed errors with no API dispatch or trap mapping. |
| A copied five-byte x86 prologue truncates a jump | `8B FF 0F 1F 00` occupies the first five bytes; the relative jump starts at byte five. A real guest copied-prologue trampoline runs correctly for a catalog entry, with tracing on/off. A symbol test pins the entry bytes, including the extra NOP. |
| Failed loads consume tokens or arena allocation exhausts | Tokens remain monotonic and retired to prevent aliasing. Capacity failure is bounded and preserves survivors, public addresses, registry ownership, bytes and graph rollback. A test fills the 2,048-entry dynamic arena and checks that refusal leaves existing addresses and bytes unchanged. |
| Mapping checks reject inconsistent PE headers | These remain mandatory: machine/magic disagreement, impossible section spans and absent required relocation data cannot be repaired by dropping an optional directory. Lenient inventories do not authorize incoherent memory mappings. |
| Exact Windows exports exceed declaration catalogs | User modules with a physical export manifest (Windows Server 2025, 10.0.26100) take names and ordinals from it, including undocumented and ordinal-only exports. Forwarders are recorded but not applied. Kernel modules and modules absent from the source installation still use declaration catalogs. A manifest describes one build, so names and ordinals that changed between builds can differ from older Windows versions. |
| Known unsupported declarations and unknown x86 ABIs | Unsupported float/aggregate return handling and undeclared x86 cleanup remain explicit failures. The permissive Win64 fallback only applies to wholly undeclared scalar calls. Stack-safe cleanup alone cannot supply missing float/aggregate return values. |
| Python instruction callbacks and host cache invalidation cost time | Exact capped accounting still requires Python callbacks; this performance regression is documented rather than hidden by approximate counting. Host patch invalidation preserves guest-visible changes; the measured API dispatch improvement does not isolate cache costs. |

The migration guide enumerates removed sentinel/import-table/data contracts, native guest execution, hook return requirements and debugger limits. Automated RSP tests validate the protocol; they do not establish a live IDA or VMRay integration smoke test. Focused commits improve reviewability, but the PR has not been split into separate PRs. Kernel-mode export manifests and a representative modern malware evaluation remain separate requirements for stronger fidelity claims.

### Physical export inventory checks

The pinned capa fixtures provide two physical kernel32 files from other Windows builds. Comparing their named EAT exports with the manifest-backed synthetic kernel32 finds:

| Fixture | Version | Physical named exports | Missing from synthetic kernel32 | Synthetic-only names |
| --- | --- | ---: | ---: | ---: |
| `kernel32.dll_` (x86) | 6.1.7601.17514 | 1,359 | 16 | 324 |
| `kernel32-64.dll_` (x64) | 10.0.17134.1 | 1,621 | 3 | 81 |

The missing names are exports that Windows Server 2025 no longer has, such as `NlsWriteEtwEvent` and `BaseVerifyUnicodeString`. The synthetic-only names are mostly exports added in later builds, plus a few handler names such as `EnumProcesses`. `BaseThreadInitThunk` and `RtlFillMemory` are physical exports of the manifest build and appear in the synthetic table. Native parsing retains the physical `AcquireSRWLockExclusive -> NTDLL.RtlAcquireSRWLockExclusive` forwarder; the synthetic table has a local mapped entry for the same name. `tests/test_pinned_export_catalog.py` pins hashes and tests GetProcAddress/Ldr queries for an export that the manifest build does not have, before and after an explicit dynamic import request.

### Shellcode and CRT frame controls

Input-string extraction includes both guest PE and guest shellcode sources, while excluding synthetic export inventories. Public x86 tests cover ANSI/UTF-16 input literals and strings constructed by actual guest stack stores. An `_EH_prolog` test executes its guest caller and verifies FS:[0], saved EBP/SP, argument preservation and both continuations with an existing exception chain. These tests supplement indirect corpus evidence.

### Expanded corpus comparison

The additional pass compares six feature-selected images and a filename-sorted census of 128 native PEs on separate baseline and revised trees. Three images overlap, giving 131 distinct additional inputs. The census excludes the previous 24 cases, PMA, managed images, the physical kernel32 controls, files above 2 MiB and mapped images above 32 MiB. Three feature selections have matching CAPE observation reports from October 2023 (including SunCrypt); the other three are BCrypt/WinHTTP/TLS controls, without an age or family claim. Observation dates are not compilation dates.

Profiles use timeout 2 seconds, API limit 200 and the main/attach entry only. Revised code uses an aggregate 2-second active cap to approximate baseline's invocation-wide native timeout while retaining the same per-run timeout. Inputs are hash-pinned and measurements serialized.

| Group / tree | Inputs | Runs | Recorded API events | Load exceptions | Total wall time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Six selections / baseline | 6 | 9 | 386 | 0 | 0.790s |
| Six selections / revised | 6 | 9 | 387 | 0 | 0.931s |
| Census / baseline | 128 | 165 | 11,928 | 0 | 35.123s |
| Census / revised | 128 | 165 | 12,128 | 0 | 30.996s |

All six selections preserve their error categories. One x64 CRT case routes API-set calls to their actual msvcrt owner and advances from memcpy to isalnum before another unsupported call. Of 134 comparison executions, 119 retain error sequences and 68 retain function-name sequences (58 retain exact DLL-qualified sequences). These are descriptive checks, not a claim of uniformly greater coverage. Changed error tails need causal investigation; aggregate event counts alone are insufficient. Attach-only DLL execution also does not reproduce an external sandbox's rundll32 export invocation.

A fresh x86/x64 constructed-PE report additionally passes the parent Speakeasy parser, importer and SQLite trace-store pipeline, with tracing, coverage and snapshots enabled. Assertions check primary-module identity, addresses, section permissions, dynamic API events, guest writes into CRT data and database integrity. This tests the report producer/consumer path without parent edits, Qt or IDA. Live IDA symbol naming, rebasing, multi-process attribution and VMRay archive compatibility remain unverified.

The census also exposes an earlier stop in a Borland startup image (`4bdd67ff852c221112337fecd0681eac.exe_`). Both trees first return the executable base from GetModuleHandleA(NULL). The guest then writes that value into imported `rtl60!@System@MainInstance` and sets `@System@IsMultiThread`. Baseline materializes RWX sentinel pages for these data accesses before eventually stopping at unsupported runtime initialization. Revised code correctly protects synthetic function entries RX, but unknown Borland variable imports were classified as functions and the first store faults. This is missing data-export metadata and a coverage limit, not an API-header patch or a successful baseline payload lost. Known variable declarations should use explicit writable data exports; making every callable page writable would conceal the classification defect. ErrorInfo's allocator-level region protection can be stale after partial protection changes; native engine regions and captured section permissions are authoritative.

The unpacker case `0cd2b334aede270b14868db28211cde3.exe_` explains another changed tail. Baseline's apparently clean GUI path reports unresolved hash `A92D71B2`, identifying SetWindowRgn; it is an unpacking failure. Revised code resolves that export and reaches 87 distinct successful GetProcAddress requests before the same two-second budget expires during import reconstruction. No fault-recovery callbacks were observed. This demonstrates resolution progress, not established payload execution or a general performance conclusion.
