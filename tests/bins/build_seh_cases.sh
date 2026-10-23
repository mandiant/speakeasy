#!/bin/sh
# Build seh_cases.c for x64 and x86 without a CRT or SDK, against import
# libraries for its few imports, into seh_cases_x64.exe.xz and seh_cases_x86.exe.xz.
# Needs clang-cl, lld-link and llvm-dlltool.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

printf 'LIBRARY KERNEL32.dll\nEXPORTS\nRaiseException\nAddVectoredExceptionHandler\nRtlMoveMemory\nSetThreadContext\n' > kernel32_x64.def
printf 'LIBRARY VCRUNTIME140.dll\nEXPORTS\n__C_specific_handler\n' > vcruntime140.def
llvm-dlltool -m i386:x86-64 -d kernel32_x64.def -l kernel32_x64.lib
llvm-dlltool -m i386:x86-64 -d vcruntime140.def -l vcruntime140.lib
clang-cl --target=x86_64-pc-windows-msvc /O1 /GS- /c "$here/seh_cases.c" /Foseh_cases_x64.obj
lld-link /nodefaultlib /entry:main /subsystem:console /out:seh_cases_x64.exe seh_cases_x64.obj kernel32_x64.lib vcruntime140.lib

printf 'LIBRARY KERNEL32.dll\nEXPORTS\nRaiseException@16\nAddVectoredExceptionHandler@8\nRtlMoveMemory@12\nSetThreadContext@8\n' > kernel32_x86.def
printf 'LIBRARY msvcrt.dll\nEXPORTS\n_except_handler3\n' > msvcrt.def
llvm-dlltool -m i386 -k -d kernel32_x86.def -l kernel32_x86.lib
llvm-dlltool -m i386 -d msvcrt.def -l msvcrt.lib
clang-cl --target=i686-pc-windows-msvc /O1 /GS- /c "$here/seh_cases.c" /Foseh_cases_x86.obj
lld-link /nodefaultlib /entry:main /subsystem:console /safeseh:no /out:seh_cases_x86.exe seh_cases_x86.obj kernel32_x86.lib msvcrt.lib

xz -9 -c seh_cases_x64.exe > "$here/seh_cases_x64.exe.xz"
xz -9 -c seh_cases_x86.exe > "$here/seh_cases_x86.exe.xz"
