#!/bin/sh
# Build seh_cases.c and seh_cases_cxx.cpp for x64 and x86 without a CRT or SDK, against
# import libraries for their few imports, into seh_cases_x64.exe.xz and seh_cases_x86.exe.xz.
# Needs clang-cl, lld-link, llvm-dlltool, and xz or python3.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

printf 'LIBRARY KERNEL32.dll\nEXPORTS\nRaiseException\nAddVectoredExceptionHandler\nRtlMoveMemory\nSetThreadContext\n' > kernel32_x64.def
printf 'LIBRARY VCRUNTIME140.dll\nEXPORTS\n__C_specific_handler\n__CxxFrameHandler3\n' > vcruntime140.def
llvm-dlltool -m i386:x86-64 -d kernel32_x64.def -l kernel32_x64.lib
llvm-dlltool -m i386:x86-64 -d vcruntime140.def -l vcruntime140.lib
clang-cl --target=x86_64-pc-windows-msvc /O1 /GS- /EHa /c /Foseh_cases_x64.obj -- "$here/seh_cases.c"
clang-cl --target=x86_64-pc-windows-msvc /O1 /GS- /GR- /EHa /c /Foseh_cases_cxx_x64.obj -- "$here/seh_cases_cxx.cpp"
lld-link /brepro /nodefaultlib /entry:main /subsystem:console /out:seh_cases_x64.exe seh_cases_x64.obj seh_cases_cxx_x64.obj \
    kernel32_x64.lib vcruntime140.lib

printf 'LIBRARY KERNEL32.dll\nEXPORTS\nRaiseException@16\nAddVectoredExceptionHandler@8\nRtlMoveMemory@12\nSetThreadContext@8\n' > kernel32_x86.def
printf 'LIBRARY ntdll.dll\nEXPORTS\nRtlCaptureContext@4\nNtContinue@8\n' > ntdll_x86.def
printf 'LIBRARY msvcrt.dll\nEXPORTS\n_except_handler3\n__CxxFrameHandler3\n' > msvcrt.def
llvm-dlltool -m i386 -k -d kernel32_x86.def -l kernel32_x86.lib
llvm-dlltool -m i386 -k -d ntdll_x86.def -l ntdll_x86.lib
llvm-dlltool -m i386 -d msvcrt.def -l msvcrt.lib
clang-cl --target=i686-pc-windows-msvc /O1 /GS- /EHa /c /Foseh_cases_x86.obj -- "$here/seh_cases.c"
clang-cl --target=i686-pc-windows-msvc /O1 /GS- /GR- /EHa /c /Foseh_cases_cxx_x86.obj -- "$here/seh_cases_cxx.cpp"
lld-link /brepro /nodefaultlib /entry:main /subsystem:console /safeseh:no /out:seh_cases_x86.exe seh_cases_x86.obj \
    seh_cases_cxx_x86.obj kernel32_x86.lib ntdll_x86.lib msvcrt.lib

for arch in x64 x86; do
    if command -v xz >/dev/null; then
        xz -9 -c "seh_cases_$arch.exe" > "$here/seh_cases_$arch.exe.xz"
    else
        python3 -c 'import lzma, sys; sys.stdout.buffer.write(lzma.compress(open(sys.argv[1], "rb").read(), preset=9))' \
            "seh_cases_$arch.exe" > "$here/seh_cases_$arch.exe.xz"
    fi
done
