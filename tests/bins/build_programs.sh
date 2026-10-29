#!/bin/sh
# Build the small test programs of this directory without a CRT or SDK, against import
# libraries for their few imports, into <name>_<arch>.exe.xz.
# Needs clang-cl, lld-link, llvm-dlltool, llvm-rc, and xz or python3.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# implib ARCH DLL EXPORT...: write DLL_ARCH.lib. x86 stdcall exports end in @<argument bytes>.
implib() {
    arch=$1 dll=$2
    shift 2
    printf 'LIBRARY %s.dll\nEXPORTS\n' "$dll" > "${dll}_$arch.def"
    printf '%s\n' "$@" >> "${dll}_$arch.def"
    if [ "$arch" = x64 ]; then
        llvm-dlltool -m i386:x86-64 -d "${dll}_$arch.def" -l "${dll}_$arch.lib"
    else
        llvm-dlltool -m i386 -k -d "${dll}_$arch.def" -l "${dll}_$arch.lib"
    fi
}

# program SOURCE OUTPUT ARCH LINK_ARGUMENT...: compile SOURCE.c with the options in $cflags, link it,
# and write OUTPUT_ARCH.exe.xz
program() {
    source=$1 output=$2 arch=$3
    shift 3
    if [ "$arch" = x64 ]; then target=x86_64-pc-windows-msvc; else target=i686-pc-windows-msvc; fi
    clang-cl --target=$target /O1 /GS- /Oi- $cflags /c /Fo"${source}_$arch.obj" -- "$here/$source.c"
    lld-link /brepro /nodefaultlib /entry:main /subsystem:console /out:"${output}_$arch.exe" "${source}_$arch.obj" "$@"
    if command -v xz >/dev/null; then
        xz -9 -c "${output}_$arch.exe" > "$here/${output}_$arch.exe.xz"
    else
        python3 -c 'import lzma, sys; sys.stdout.buffer.write(lzma.compress(open(sys.argv[1], "rb").read(), preset=9))' \
            "${output}_$arch.exe" > "$here/${output}_$arch.exe.xz"
    fi
}

implib x64 KERNEL32 Sleep IsProcessorFeaturePresent CreateFileA WriteFile CloseHandle
implib x86 KERNEL32 Sleep@4 IsProcessorFeaturePresent@4 CreateThread@24 ExitThread@4 GetExitCodeThread@8 CreateFileA@28 \
    WriteFile@20 CloseHandle@4 LocalAlloc@8 CreateProcessA@40 GetTickCount@0
implib x64 bcrypt BCryptOpenAlgorithmProvider BCryptSetProperty BCryptGenerateSymmetricKey BCryptGetProperty \
    BCryptEncrypt BCryptDecrypt BCryptDestroyKey
implib x86 bcrypt BCryptOpenAlgorithmProvider@16 BCryptSetProperty@20 BCryptGenerateSymmetricKey@28 BCryptGetProperty@24 \
    BCryptEncrypt@40 BCryptDecrypt@40 BCryptDestroyKey@4
implib x64 msvcrt pow floor ceil sin fmod ceilf floorf
implib x86 USER32 DialogBoxParamA@20 EndDialog@8 EnumWindows@8 CreateWindowExA@48 RegisterClassExA@4 DefWindowProcA@16
implib x86 ole32 CoInitializeEx@8 CoCreateInstance@20
implib x86 msvcrt pow floor ceil sin fmod _CIfmod _beginthread _endthread _endthreadex

cflags=
for arch in x64 x86; do
    program cpu_cases cpu_cases $arch KERNEL32_$arch.lib
done
program float_cases float_cases x64 msvcrt_x64.lib
# x87 only, so that no double that the code passes on the stack is also in an XMM register
cflags=/arch:IA32
program float_cases float_cases x86 msvcrt_x86.lib
cflags=
program thread_cases thread_cases x86 KERNEL32_x86.lib msvcrt_x86.lib
llvm-rc /fo window_cases.res -- "$here/window_cases.rc"
program window_cases window_cases x86 USER32_x86.lib window_cases.res
program wmi_cases wmi_cases x86 ole32_x86.lib
for arch in x64 x86; do
    program bcrypt_cases bcrypt_cases $arch bcrypt_$arch.lib KERNEL32_$arch.lib
done
program parent parent x86 KERNEL32_x86.lib
program child child x86
program child child_at_10000000 x86 /base:0x10000000
program api_loop api_loop x86 KERNEL32_x86.lib
