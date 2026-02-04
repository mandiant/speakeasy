# Reporting
---
When samples have finished emulating, an emulation report can be obtained, containing all the events that were captured while executing. This report is currently formatted as a JSON object. The fields in the JSON report contain event types such as memory and object access, API calls with arguments, network activity, file system access, and other meta data.

## Report Format
---
* path
    * Local path of the file that was emulated
* sha256
    * Hash of the file that was emulated
* size
    * Size of the file that was emulated
* arch
    * Architecture of the emulated file
* emu_version
    * Version of the emulator that generated the report
* os_run
    * The operating system version that was presented during emulation
* report_version
    * Version of the format of the generated report (2.0.0)
* emulation_total_runtime
    * Total time spent emulating the sample in seconds
* timestamp
    * Time at which the sample was emulated in epoch
* strings
    * static
        * Strings found in the static image of the emulated sample
    * in_memory
        * Strings found at runtime in memory (not found in the static strings)
* entry_points
    * List of entry points that were emulated (in order). This includes all execution primitives such as threads, child processes, or callbacks.
    * ep_type
        * The type of entry point that was logged. This can be any execution primitive including an injected thread, a driver IRP handler, or a DLL export.
    * start_addr
        * The virtual address where emulation began
    * apihash
        * As API functions are emulated their names are hashed. This can potentially be used to find similar entry points across samples regardless of architecture.
    * ret_val
        * Value returned by the entry point
    * error
        * Any errors during emulation are logged here included a Python stack trace if applicable. Additionally, if the emulated sample encounters a memory access error, the CPU register and stack state are logged here.
    * events
        * Unified chronological list of all events captured during emulation. Events are ordered by `tick` (instruction count). All events have:
            * tick - instruction count at time of event
            * tid - thread ID
            * event - event type
        * Event types:
            * api - API call
                * pc - return address
                * api_name - module.function name
                * args - list of arguments
                * ret_val - return value
            * process_create - child process creation
                * pid - process ID
                * path - process path
                * cmdline - command line
            * mem_alloc - remote memory allocation
                * pid, path - target process
                * base, size - allocated region
                * protect - protection flags
            * mem_write - remote memory write
                * pid, path - target process
                * base, size - written region
                * data - base64 encoded data
            * mem_read - remote memory read
                * pid, path - target process
                * base, size - read region
                * data - base64 encoded data
            * mem_protect - remote memory protection change
                * pid, path - target process
                * base, size - protected region
                * protect - new protection flags
            * thread_create - thread creation in remote process
                * pid, path - target process
                * start_addr - thread entry point
                * param - thread parameter
            * thread_inject - thread injection
                * pid, path - target process
                * start_addr - thread entry point
                * param - thread parameter
            * file_create - file creation
                * path - file path
                * handle - file handle
                * open_flags, access_flags - creation flags
            * file_open - file open
                * path - file path
                * handle - file handle
                * open_flags, access_flags - open flags
            * file_read - file read
                * path - file path
                * handle, size, data, buffer
            * file_write - file write
                * path - file path
                * handle, size, data, buffer
            * reg_open_key - registry key open
                * path - registry path
                * handle - key handle
                * open_flags, access_flags
            * reg_create_key - registry key creation
                * path - registry path
                * handle - key handle
                * open_flags, access_flags
            * reg_read_value - registry value read
                * path - registry path
                * handle, value_name, size, data, buffer
            * reg_list_subkeys - registry subkey enumeration
                * path - registry path
                * handle
            * net_dns - DNS query
                * query - domain name
                * response - resolved IP
            * net_traffic - network connection
                * server - remote server
                * port - remote port
                * proto - protocol
                * type - connection type
                * data - base64 encoded data
                * method - connection method
            * net_http - HTTP request
                * server, port, proto
                * headers, body
            * exception - handled exception
                * pc - exception address
                * instr - faulting instruction
                * exception_code - exception code
                * handler_address - SEH handler address
                * registers - CPU register state
    * mem_access
        * When memory tracing is enabled, log all access to each memory block
        * tag
            * Tag of the memory block that was accessed
        * base
            * Base virtual address of the memory block that was accessed
        * reads
            * Number of times the memory block was read from
        * writes
            * Number of times the memory block was written to
        * execs
            * Number of times the memory block was executed from
    * sym_accesses
        * When memory tracing is enabled, log all access to symbols within the emulation environment. For example, when shellcode is manually parsing an export table to call an API function, the function that was accessed will be logged.
    * dropped_files
        * Files that are written to disk are logged here.
    * dynamic_code_segments
        * When code is dynamically allocated and executed at runtime, these segments are logged here. This can be useful in identifying samples unpacking themselves.


Below is an example output JSON report of a shellcode payload that executes a reverse shell:
```json
{
    "path": "/sandbox/sc.bin",
    "sha256": "01a1b13281b7fb50740f945b4f205bbdf32399844c2264bbe027dd6447f29e40",
    "size": 324,
    "arch": "x86",
    "mem_tag": "emu.shellcode.01a1b13281b7fb50740f945b4f205bbdf32399844c2264bbe027dd6447f29e40",
    "emu_version": "1.4.4",
    "os_run": "windows.6_1",
    "report_version": "2.0.0",
    "emulation_total_runtime": 1.084,
    "timestamp": 1596556067,
    "strings": {
        "static": {
            "ansi": [
                ";}$u",
                "D$$[[aYZQ",
                "]h32",
                "hws2_ThLw&",
                "TPh)",
                "PPPP@P@Ph",
                "hcmd",
                "WWW1",
                "DTPVVVFVNVVSVhy"
            ],
            "unicode": []
        },
        "in_memory": {
            "ansi": [
                "ws2_32"
            ],
            "unicode": []
        }
    },
    "entry_points": [
        {
            "ep_type": "shellcode",
            "start_addr": "0x1000",
            "ep_args": [
                "0x41420000",
                "0x41421000",
                "0x41422000",
                "0x41423000"
            ],
            "instr_count": 345329,
            "apihash": "3b818f37253eb7d32c030b29fea97caf76c3199f9263fbca93268c096794605f",
            "ret_val": "0x770002ac",
            "error": {},
            "events": [
                {
                    "tick": 100,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x109b",
                    "api_name": "kernel32.LoadLibraryA",
                    "args": [
                        "ws2_32"
                    ],
                    "ret_val": "0x78c00000"
                },
                {
                    "tick": 200,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x10ab",
                    "api_name": "ws2_32.WSAStartup",
                    "args": [
                        "0x190",
                        "0x1203e4c"
                    ],
                    "ret_val": "0x0"
                },
                {
                    "tick": 300,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x10ba",
                    "api_name": "ws2_32.WSASocketA",
                    "args": [
                        "AF_INET",
                        "SOCK_STREAM",
                        "0x0",
                        "0x0",
                        "0x0",
                        "0x0"
                    ],
                    "ret_val": "0x4"
                },
                {
                    "tick": 400,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x10d4",
                    "api_name": "ws2_32.connect",
                    "args": [
                        "0x4",
                        "127.0.0.1:4444",
                        "0x10"
                    ],
                    "ret_val": "0x0"
                },
                {
                    "tick": 410,
                    "tid": 1000,
                    "event": "net_traffic",
                    "server": "127.0.0.1",
                    "port": 4444,
                    "proto": "tcp",
                    "method": "winsock.connect",
                    "type": "connect"
                },
                {
                    "tick": 500,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x1117",
                    "api_name": "kernel32.CreateProcessA",
                    "args": [
                        "0x0",
                        "cmd",
                        "0x0",
                        "0x0",
                        "0x1",
                        "0x0",
                        "0x0",
                        "0x0",
                        "0x1203df8",
                        "0x1203de8"
                    ],
                    "ret_val": "0x1"
                },
                {
                    "tick": 510,
                    "tid": 1000,
                    "event": "process_create",
                    "pid": 1208,
                    "path": "C:\\Windows\\system32\\cmd",
                    "cmdline": "cmd"
                },
                {
                    "tick": 600,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x1125",
                    "api_name": "kernel32.WaitForSingleObject",
                    "args": [
                        "0x220",
                        "0xffffffff"
                    ],
                    "ret_val": "0x0"
                },
                {
                    "tick": 700,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x1131",
                    "api_name": "kernel32.GetVersion",
                    "args": [],
                    "ret_val": "0x1db10106"
                },
                {
                    "tick": 800,
                    "tid": 1000,
                    "event": "api",
                    "pc": "0x1144",
                    "api_name": "kernel32.ExitProcess",
                    "args": [
                        "0x0"
                    ],
                    "ret_val": "0x0"
                }
            ],
            "mem_access": [
                {
                    "tag": "emu.shellcode.01a1b13281b7fb50740f945b4f205bbdf32399844c2264bbe027dd6447f29e40.0x1000",
                    "base": "0x1000",
                    "reads": 0,
                    "writes": 0,
                    "execs": 345329
                },
                {
                    "tag": "emu.stack.0x1200000",
                    "base": "0x1200000",
                    "reads": 7855,
                    "writes": 210,
                    "execs": 0
                },
                {
                    "tag": "emu.segment.fs.0x4000",
                    "base": "0x4000",
                    "reads": 8,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.PEB.0x1150",
                    "base": "0x1150",
                    "reads": 8,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.PEB_LDR_DATA.0x6000",
                    "base": "0x6000",
                    "reads": 8,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.LDR_DATA_TABLE_ENTRY.0x11d0",
                    "base": "0x11d0",
                    "reads": 176,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.module.main.0x400000",
                    "base": "0x400000",
                    "reads": 16,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.LDR_DATA_TABLE_ENTRY.0x1290",
                    "base": "0x1290",
                    "reads": 235,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.module.kernel32.0x77000000",
                    "base": "0x77000000",
                    "reads": 53262,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.LDR_DATA_TABLE_ENTRY.0x1350",
                    "base": "0x1350",
                    "reads": 72,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.module.ntdll.0x7c000000",
                    "base": "0x7c000000",
                    "reads": 8892,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.struct.LDR_DATA_TABLE_ENTRY.0x1410",
                    "base": "0x1410",
                    "reads": 75,
                    "writes": 0,
                    "execs": 0
                },
                {
                    "tag": "emu.module.ws2_32.0x78c00000",
                    "base": "0x78c00000",
                    "reads": 3951,
                    "writes": 0,
                    "execs": 0
                }
            ],
            "dynamic_code_segments": []
        }
    ]

}
```
