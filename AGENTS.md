# Instructions for agents

## How to model Windows behavior

Speakeasy is an approximation of Windows. Code that is easy to understand is more important than behavior that is complex and exact.

Add or change a model of a Windows behavior only when one of these conditions is true:

1. Frequent malware needs the behavior to continue.
2. Without the behavior, the report or the dropped files are incorrect or incomplete. An incorrect report is worse than a missing behavior.
3. Without the behavior, the state of the emulator becomes inconsistent. Examples are a crash, memory corruption and a hang.

If no condition is true:

- Keep the API handler stateless, and return success.
- Do not add a partial model. A reader trusts a partial model, but it is not correct. If a handler keeps a partial state, remove the state. Do not complete it.
- Write the approximation in the docstring of the handler, so that a reader knows that it is a decision and not an error.

When a handler must keep state that the guest can see, put the state on the `Process` or `Thread` object. One handler instance serves all processes and threads.
