# Limitations

Since we do not rely on a physical OS to handle API calls, object and memory allocation, and I/O operations, these responsibilities fall to the emulator. Upon emulating multiple samples, users are likely to encounter samples that do not fully emulate. This can most likely be attributed to missing API handlers, specific OS implementation  details, or environmental factors.

## Unimplemented APIs

Malware samples will call system APIs to interact with the OS. For example, on Windows systems samples will typically open files using the CreateFile* API set. This will invoke the emulator to search for a handler for this specific API. The API handlers are expected to handle expected inputs and outputs for the function. This will vary function by function depending on what the malware expects to get returned. For many API handlers, simply returning a success code will be sufficient to make the malware to continue execution. The goal here is to allow the malware to emulate until most of its functionality can be recorded. 

When the system encounters an API that does not have a handler, the current run is recorded and stopped. Since we don't know the amount of arguments the unhandled API requires, the stack would be corrupt on return. This was a design choice in order to avoid potentially spurious report details. If there are other queued runs such as new threads or exports, they will still be emulated.

When unsupported APIs are encountered, the error message: `Unsupported API: <module_name>.<api_name>` is presented to the user and logged in the report.

For how to add API handlers that are not currently supported see [Adding API handlers](../README.md).

## Environmental requirements

Other reasons a sample may fail to fully emulate can be related to its expected environment. This may include files or registry keys that the malware expected to be present and weren't found or unexpected data returned by the emulated network. These types of "misses" can be configured in the supplied config file for each emulation run. (See [configuration](configuration.md) for more details.)

Environment details that are harder to deal with include opaque data structures that are expected to be preallocated by the OS, specific details about loaded code modules, or CPU specific data. These types of issues would require an update to the emulator code itself and need to be addressed on a case by case basis.
