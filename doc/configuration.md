# Configuration
---
Speakeasy uses configuration files that describe the environment that is presented to emulated binaries. This includes OS specific fields such as OS version, environment variables, loaded user and system modules, and running processes. In addition, more complex OS components such as networking, file systems, object management and the registry are emulated in an attempt to simulate a full Windows operating system as much as possible. The fields in the config file can be customized to create easily interchangable simulated environments. For example, if a sample expects a specific process to be running at execution time, this can easily be added to a config file. 
The specifics to how this simulation is presented to emulated binaries are described in JSON configuration files.

The fields supported by these configuration files are documented below:

* config_version
    * The current version of the config file (currently: 1.1.0).
* emu_engine
    * Backend CPU emulator to use. Currently, only the unicorn engine is supported.
* timeout
    * Indicates the maximum number seconds to run the emulator.
* max_api_count
    * Maximum number of API calls per execution run before continuing to the next run.
* analysis
    * Identifies different analysis options (note: these may affect emulation speed).
    * memory_tracing
        * When true, memory access to each memory block is logged. This can identify activity such as hooking or PEB walking.
    * strings
        * Acquires strings from memory after emulation completion.
* keep_memory_on_free
    * Denies free'ing of memory blocks so that all memory allocated by the sample can be analyzed.
* exceptions
    * Identifies different exception handling options; specifically CPU exceptions
        * dispatch_handlers
            * If set to “true”, the emulator will attempt to dispatch exception handlers registered by the application (e.g. SEH handlers). Otherwise, emulation will stop when a CPU exception occurs.
* os_ver
    * Defines the version of the operating system to present to emulated binaries
    * This field allows the user to set version specific information such as major, minor, and build number
* current_dir
    * Sets the currently working directory presented to the emulated sample
* command_line
    * Sets the command line returned to the sample when queried
* env
    * Sets environment variables presented to emulated binaries
* hostname
    * Sets the Hostname returned when queried
* user
    * Sets user specific options that are returned to samples
        * name
            * Sets the current user name
        * is_admin
            * Specifies whether the current user is identified as an administrator
* symlinks
    * Allows the user to set symbolic links to devices (e.g. having “C:\” point to “\Device\HarddiskVolume1”
* filesystem
    * An attempt is made to create a mock file system by allowing users to supply handlers when samples try to access files during emulation. This field allows users to specify what data will be returned when specific files are accessed, or what data is returned for certain extensions (e.g. .exe, .dll, .txt).
    * Each handler entry describes how to handle specific file access scenarios and are described below:
        * mode - Describes how to match on file accesses
            * full_path
                * Matches on access of a full file path: (e.g. C:\Temp\myfile.bin)
            * by_ext
                * Matches on any file with the specified file extension
            * default
                * If no other filter matches, this handler is used
* registry
    * An attempt is made to create a mock registry by allowing users to supply handlers when samples try to access registry keys and values during emulation
    * Each handler entry describes how to handle specific keys and value paths
* network
    * Creates a mock network manager that allows emulated samples to think they are connected to a real network. This includes allowing the user to configure DNS responses, HTTP responses (including reply data), and socket connections  
        * dns
            * names
                * Specifies specific IP addresses returned during domain name queries
            * txt
                * Specifies data returned during DNS TXT queries
        * http
            * Describes how to respond to specific HTTP requests.
        * winsock
            * Describes how to respond to binary TCP/UDP traffic.
* processes
    * Defines the processes that will be presented to the emulated sample when queried. The full path of the main process image along with command line arguments and base load address can be specified. This can be useful when emulated samples expect a specific process environment. When "is_main_exe" is set, this will be used as the main container process for shellcode or DLLs that do not normally have a process object created by default. Additionally, the session the process is being executed in can specified.
* modules
    * modules_always_exist
        * When "true" module loads will always succeed in order to satisfy dynamic library loads. Otherwise if unavailable, a "module not found" error will be returned. This can be used to set the emulation evironment to be similar to what samples expect.
    * module_directory_x86
        * Sets the directory that will be searched for when modules are dynamically loaded at runtime (for 32-bit binaries). This is often necessary for shellcode that will manually parse module export tables to find API functions. Arbitrary files can be placed in this directory that will be loaded when "LoadLibrary" style functions are called and the files will be mapped into the emulated address space.
    * module_directory_x64
        * This is the same as the "module_directory_x86" field except it applies to 64-bit binaries.
    * system_modules
        * Defines the system modules (e.g. drivers) that will be presented to the emulated sample when queried. The base load address for each module can be specified along with the full module path. In addition, a supplied module can be loaded into the emulated address space in order to support samples that manually parse PE headers for export resolution. Driver and device objects can also be attributed to system modules using their corresponding fields (see the default configuration for an example).
    * user_modules
        * Defines the user modules (e.g. DLLs) that will be presented to the emulated sample when queried. The base load address for each module can be specified along with the full module path. In addition, a supplied module can be loaded into the emulated address space in order to support samples that manually parse PE headers for export resolution. Note: the order is maintained when loaded into the PEB load order module list for older malware samples that expected the module list to be in a certain order (e.g. kernel32 to be located second in the linked list).
