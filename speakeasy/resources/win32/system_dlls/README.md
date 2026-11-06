# System directory DLLs

`x64.txt` and `x86.txt` list the DLL file names in the system directory of a clean Windows install. `x64.txt` has the names in `Windows\System32`. `x86.txt` has the names in `Windows\SysWOW64`, which an x86 process sees as its system directory. The names are in lower case and sorted, one name on each line.

`LoadLibrary` uses these lists for a DLL that has no handler, no declaration in the signature databases and no file in the module directory. If the list of the process architecture has the file name, the load gives a synthetic module without exports, and `GetProcAddress` fails for each function of that module. If the list does not have the file name, the load fails. A name without an extension gets `.dll`, as in Windows. With `modules.modules_always_exist`, the load of each unknown DLL succeeds, and Speakeasy does not use the lists.

The lists come from [winbindex](https://github.com/m417z/winbindex) for Windows 11 version 24H2, build 10.0.26100.1. For each release, winbindex records the files of the install image (`sources\install.wim`, all editions) of the release ISO, in the `BASE` entry of each file. The ISO of this release has the SHA-256 `26ea802d680de069cb3d7ed9104b59b442122fa6d8c9db511a133c00593cfe8c`. It is the same build as the export manifests in `exports/`, but a client release, because winbindex has no Server releases. The lists have only `.dll` names.

To make the lists again, run:

```bash
python scripts/gen_system_dlls.py --release 11-24H2 --cache /tmp/winbindex
```

The script downloads `filenames.json` and the record of each DLL name from https://winbindex.m417z.com/data/, about 9,700 files and 390 MB, into the cache directory. Then it keeps the names that the `BASE` entry of the release has in `Windows\System32` or `Windows\SysWOW64`. Another winbindex release key, such as `22H2`, gives the lists of that release.

Each module of `exports/` is in the list of its architecture, except `wdmaud.drv` and the modules that the sogen root gets from other installers: `d3dcompiler_43`, `x3daudio1_7`, `xapofx1_5`, `xinput1_3` (DirectX June 2010 redistributable) and the x64 `d3d8`.
