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

implib x64 KERNEL32 Sleep IsProcessorFeaturePresent
implib x86 KERNEL32 Sleep@4 IsProcessorFeaturePresent@4

cflags=
for arch in x64 x86; do
    program cpu_cases cpu_cases $arch KERNEL32_$arch.lib
done
