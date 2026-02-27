# Speakeasy overview

Speakeasy is a portable, modular binary emulator for Windows user-mode and kernel-mode malware analysis.

Instead of relying on a full virtualized operating system, Speakeasy models specific Windows components, including APIs, objects, process/thread behavior, filesystem behavior, and network behavior.

Before emulation, Speakeasy identifies entry points and executes them in sequence. Exported functions are emulated, and runtime-discovered entry points (for example new threads, callbacks, and handler paths) are queued so behavior can be attributed per entry point.

The current implementation is Python-based and uses Unicorn for CPU emulation. API behavior is implemented in Python handlers to keep samples on expected execution paths.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Limitations](limitations.md)
- [Help and troubleshooting](help.md)
