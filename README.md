# Speakeasy

Speakeasy is a portable, modular, binary emulator designed to emulate Windows kernel and user mode malware.

Check out the overview in the first [Speakeasy blog post](https://www.fireeye.com/blog/threat-research/2020/08/emulation-of-malicious-shellcode-with-speakeasy.html).

Instead of attempting to perform dynamic analysis using an entire virtualized operating system, Speakeasy will emulate specific components of Windows. Specifically, by emulating operating system APIs, objects, running processes/threads, filesystems, and networks it should be possible to present an environment where samples can fully "execute". Samples can be easily emulated in a container or in cloud services which allow for great scalability of many samples to be simultaneously analyzed. Currently, Speakeasy supports both user mode and kernel mode Windows applications.

Before emulating, entry points are identified within the binary. For example, exported functions are all identified and emulated sequentially. Additionally, dynamic entry points (e.g. new threads, registered callbacks, IRP handlers) that are discovered at runtime are also emulated. The goal here is to have as much code coverage as possible during emulation. Events are logged on a per-entry-point basis so that functionality can be attributed to specific functions or exports.

Speakeasy is currently written entirely in Python 3 and relies on the [Unicorn emulation engine](https://github.com/unicorn-engine/unicorn) in order to emulate CPU instructions. The CPU emulation engine can be swapped out and there are plans to support other engines in the future.

APIs are emulated in Python code in order to handle their expected inputs and outputs in order to keep malware on their "happy path". These APIs and their structure should be consistent with the API documentation provided by Microsoft.

---

## Installation

Speakeasy can be executed in a docker container, as a stand-alone script, or in cloud services. The easiest method of installation is by first installing the required package dependencies, and then running the included setup.py script (replace "python3" with your current Python3 interpreter):
```console
cd <repo_base_dir>
python3 -m pip install -r requirements.txt
python3 setup.py install
```

A docker file is also included in order to build a docker image, however, Speakeasy's dependencies can be installed on the local system and run from Python directly.

---

### Running within a docker container

The included Dockerfile can be used to generate a docker image.

---

#### Building the docker image

1. Build the Docker image; the following commands  will create a container with the tag named "my_tag":
```console
cd <repo_base_dir>
docker build -t "my_tag" .
```

2. Run the Docker image and create a local volume in `/sandbox`:
```console
docker run -v <path_containing_malware>:/sandbox -it "my_tag"
```

## Usage

---

### As a library

Speakeasy can be imported and used as a general purpose Windows emulation library. The main public interface named `Speakeasy` should be used when interacting with the framework. The lower level emulator objects can also be used, however their interfaces may change in the future and may lack documentation.

Below is a quick example of how to emulate a Windows DLL:

```python
    import speakeasy

    # Get a speakeasy object
    se = speakeasy.Speakeasy()

    # Load a DLL into the emulation space
    module = se.load_module("myfile.dll")

    # Emulate the DLL's entry point (i.e. DllMain)
    se.run_module(module)

    # Set up some args for the export
    arg0 = 0x0
    arg1 = 0x1
    # Walk the DLLs exports
    for exp in module.get_exports():
        if exp.name == 'myexport':
            # Call an export named 'myexport' and emulate it
            se.call(exp.address, [arg0, arg1])

    # Get the emulation report
    report = se.get_report()

    # Do something with the report; parse it or save it off for post-processing
```

For more examples, see the [examples](examples/) directory.

---

### As a standalone command line tool

For users who don't wish to programatically interact with the speakeasy framework as a library, a standalone script is provided to automatically emulate Windows binaries. Speakeasy can be invoked via the `run_speakeasy.py` script located within the base repo directory. This script will parse a specified PE and invoke the appropriate emulator (kernel mode or user mode). The script's parameters are shown below.

```
usage: run_speakeasy.py [-h] [-t TARGET] [-o OUTPUT]
                        [-p [PARAMS [PARAMS ...]]] [-c CONFIG] [-m] [-r]
                        [-a ARCH] [-d DUMP_PATH] [-q TIMEOUT]
                        [-z DROP_FILES_PATH] [-l MODULE_DIR]

Emulate a Windows binary with speakeasy

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Path to input file to emulate
  -o OUTPUT, --output OUTPUT
                        Path to output file to save report
  -p [PARAMS [PARAMS ...]], --params [PARAMS [PARAMS ...]]
                        Commandline parameters to supply to emulated process
                        (e.g. main(argv)
  -c CONFIG, --config CONFIG
                        Path to emulator config file
  -m, --mem-tracing     Enables memory tracing. This will log all memory
                        access by the sample but will impact speed
  -r, --raw             Attempt to emulate file as-is with no parsing (e.g.
                        shellcode
  -a ARCH, --arch ARCH  Force architecture to use during emulation (for multi-
                        architecture files or shellcode). Supported archs: [
                        x86 | amd64 ]
  -d DUMP_PATH, --dump DUMP_PATH
                        Path to store compressed memory dump package
  -q TIMEOUT, --timeout TIMEOUT
                        Emulation timeout in seconds (default 60 sec)
  -z DROP_FILES_PATH, --dropped-files DROP_FILES_PATH
                        Path to store files created during emulation
  -l MODULE_DIR, --module-dir MODULE_DIR
                        Path to directory containing loadable PE modules. When
                        modules are parsed or loaded by samples, PEs from this
                        directory will be loaded into the emulated address
                        space
```

---

### Examples

Emulating a Windows driver:
```console
user@mybox:~/speakeasy$ python3 run_speakeasy.py -t ~/drivers/MyDriver.sys
```

Emulating 32-bit Windows shellcode:
```console
user@mybox:~/speakeasy$ python3 run_speakeasy.py -t ~/sc.bin  -r -a x86
```

Emulating 64-bit Windows shellcode and create a full memory dump:
```console
user@mybox:~/speakeasy$ python3 run_speakeasy.py -t ~/sc.bin  -r -a x64 -d memdump.zip
```

---

## Configuration

Speakeasy uses configuration files that describe the environment that is presented to the emulated binaries. For a full description of these fields see the README [here](doc/configuration.md).

---

## Memory Management

Speakeasy implements a lightweight memory manager on top of the emulator engine’s memory management. Each chunk of memory allocated by malware is tracked and tagged so that meaningful memory dumps can be acquired. Being able to attribute activity to specific chunks of memory can prove to be extremely useful for analysts. Logging memory reads and writes to sensitive data structures can reveal the true intent of malware not revealed by API call logging which is particularly useful for samples such as rootkits.

---

## Speed

Because Speakeasy is written in Python, speed is an obvious concern. Transitioning between native code and Python is extremely expensive and should be done as little as possible. Therefore, the goal is to only execute Python code when it is absolutely necessary. By default, the only events handled in Python are memory access exceptions or Windows API calls. In order to catch Windows API calls and emulate them in Python, import tables are doped with invalid memory addresses so that Python code is only executed when import tables are accessed. Similar techniques are used for when shellcode accesses the export tables of DLLs loaded within the emulated address space of shellcode. By executing as little Python code as possible, reasonable speeds can be achieved while still allowing users to rapidly develop capabilities for the framework.

---

## Limitations

Since we do not rely on a physical OS to handle API calls, object and memory allocation, and I/O operations, these responsibilities fall to the emulator. Upon emulating multiple samples, users are likely to encounter samples that do not fully emulate. This can most likely be attributed to missing API handlers, specific OS implementation  details, or environmental factors. For more details see [doc/limitations](doc/limitations.md).

---

## Module export parsing

Many malware samples such as shellcode will attempt to manually parse the export tables of PE modules in order resolve API function pointers. An attempt is made to make "decoy" export tables using the emulated function names currently supported but this may not be enough for some samples. The configuration files support two fields named `module_directory_x86` and `module_directory_x64`. These fields are directories that can contain DLLs or other modules that are loaded into the virtual address space of the emulated sample. There is also a command line option (`-l`) that can specify this directory at runtime. This can be useful for samples that do deep parsing of PE modules that are expected to be loaded within memory.

---

## Adding API handlers

 Like most emulators, API calls made to the OS are handled by the framework. Emulated API handlers can be added by simply defining a function with the correct name in its corresponding emulated module. Depending on the outputs expected by the API, it may be sufficient enough to simply return a success code. The argument count must be specified in order for the stack to be cleaned up correctly. If no calling convention is specified, stdcall is assumed. The argument list is passed to the emulated function as raw integers. 
 
 Below is an example of an API handler for the HeapAlloc function in the kernel32 module.

```python
    @apihook('HeapAlloc', argc=3)
    def HeapAlloc(self, emu, argv, ctx={}):
        '''
        DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
          HANDLE hHeap,
          DWORD  dwFlags,
          SIZE_T dwBytes
        );
        '''

        hHeap, dwFlags, dwBytes = argv

        chunk = self.heap_alloc(dwBytes, heap='HeapAlloc')
        if chunk:
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return chunk
```

---

## Further information

- [doc/configuration](doc/configuration.md)
- [doc/memory](doc/memory.md)
- [doc/reporting](doc/reporting.md)
- [doc/limitations](doc/limitations.md)
