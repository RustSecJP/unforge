#!/usr/bin/env bash
# Builds real Rust PE files (Windows .exe / .dll) into testdata/bin/pe/
# without Visual Studio, the Windows SDK or MinGW.
#
# Needs only what rustup provides:
#   rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc
#   rustup component add llvm-tools          (for llvm-ar; any toolchain)
#
# How: rust-lld links the official std rlibs of the *-pc-windows-msvc
# targets. What MSVC's own libraries would provide comes from two places:
#   * import libraries (kernel32.lib, ntdll.lib, ...) are generated with
#     llvm-dlltool from .def files. The symbols in them are taken from a first
#     link attempt (its "undefined symbol" errors), so nothing is hard-coded
#     about which Windows functions std uses; each symbol is assigned to the
#     DLL that exports it on Windows by its name (see dll_of below);
#   * the few CRT objects (entry point, TLS directory, _fltused) come from
#     crt.rs, written with global_asm!.
# The files are never run; they look like what MSVC link produces (same
# section layout, .pdata, imports, base relocations, TLS, CodeView record).
# A /MAP file is written next to every image: the ground truth for function
# addresses and names.
#
# Usage: testdata/pe/build.sh [--force]

set -uo pipefail
export LC_ALL=C TZ=UTC

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$REPO/testdata/bin/pe"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

log() { printf '%s\n' "$*" >&2; }

RUSTC="$(cd "$REPO" && rustup which rustc 2> /dev/null)" || RUSTC=rustc
SYSROOT="$("$RUSTC" --print sysroot)"
HOST="$("$RUSTC" -vV | sed -n 's/^host: //p')"

# llvm-lib and llvm-dlltool are llvm-ar under other names; take it from any toolchain that
# has llvm-tools.
LLVM_AR=""
for c in "$SYSROOT"/lib/rustlib/*/bin/llvm-ar "${RUSTUP_HOME:-$HOME/.rustup}"/toolchains/*/lib/rustlib/*/bin/llvm-ar; do
    [[ -x "$c" ]] && { LLVM_AR="$c"; break; }
done
if [[ -z "$LLVM_AR" ]]; then
    log "llvm-ar not found: run 'rustup component add llvm-tools' (any toolchain)"
    exit 2
fi
LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
[[ -x "$LLD" ]] || { log "rust-lld not found in $SYSROOT"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ln -s "$LLVM_AR" "$WORK/llvm-lib"
ln -s "$LLVM_AR" "$WORK/llvm-dlltool"
LIB="$WORK/llvm-lib"
DLLTOOL="$WORK/llvm-dlltool"

# The DLL that exports a Windows API function (by name pattern).
dll_of() {
    case "$1" in
        Nt* | Rtl[NU]* | __chkstk | _chkstk | _alloca_probe* | __alloca_probe*) echo ntdll ;;
        accept | bind | closesocket | connect | freeaddrinfo | getaddrinfo | GetHostNameW | \
            getpeername | getsockname | getsockopt | ioctlsocket | listen | recv | recvfrom | \
            select | send | sendto | setsockopt | shutdown | WSA*) echo ws2_32 ;;
        GetUserProfileDirectoryW) echo userenv ;;
        SystemFunction036 | Reg* | OpenProcessToken | GetTokenInformation) echo advapi32 ;;
        mem* | __CxxFrameHandler* | _CxxThrowException | __C_specific_handler | \
            __current_exception* | _except_handler*) echo vcruntime140 ;;
        atexit | strlen | wcslen | _o_* | abort | exit | malloc | free) echo ucrtbase ;;
        *) echo kernel32 ;;
    esac
}

# link_one <target> <machine> <crt object> <out.exe> <rustc args...>
link_one() {
    local target="$1" machine="$2" crtobj="$3" out="$4"
    shift 4
    local libs="$WORK/libs-$target" dllmachine=i386:x86-64
    [[ "$machine" == x86 ]] && dllmachine=i386
    mkdir -p "$libs"
    local base=("$RUSTC" --edition 2021 --target "$target" -C linker="$LLD" -C linker-flavor=lld-link
        -C link-arg=/errorlimit:0 -C link-arg="$crtobj"
        -C link-arg=/MAP:"${out%.*}.map" -L "$libs" -L "$WORK" "$@" -o "$out")
    local i err=""
    for i in 1 2 3 4 5 6; do
        err="$("${base[@]}" 2>&1)" && return 0
        local changed=0
        # Missing libraries: start them empty.
        while read -r l; do
            [[ -z "$l" ]] && continue
            local name="${l%.lib}"
            printf 'LIBRARY %s.dll\nEXPORTS\n' "$name" > "$libs/$name.def"
            changed=1
        done < <(grep -o "could not open '[^']*\.lib'" <<< "$err" | sed "s/could not open '//; s/'$//" | sort -u)
        # Undefined symbols: add each to the import library of its DLL.
        while read -r s; do
            [[ -z "$s" ]] && continue
            case "$s" in mainCRTStartup | _mainCRTStartup | _tls_index | __tls_index | _fltused | __fltused) continue ;; esac
            local name="$s"
            [[ "$machine" == x86 ]] && name="${name#_}"
            local d
            d="$(dll_of "${name%@*}")"
            [[ -f "$libs/$d.def" ]] || printf 'LIBRARY %s.dll\nEXPORTS\n' "$d" > "$libs/$d.def"
            grep -qx "  $name" "$libs/$d.def" || { echo "  $name" >> "$libs/$d.def"; changed=1; }
        done < <(grep -o 'undefined symbol: .*' <<< "$err" | sed 's/undefined symbol: //; s/__declspec(dllimport) //; s/^"//; s/"$//' | sort -u)
        if [[ $changed == 0 ]]; then
            log "$out: link failed:"
            log "$err" | tail -20
            return 1
        fi
        local def
        for def in "$libs"/*.def; do
            local n
            n="$(basename "$def" .def)"
            # dlltool (MinGW mode) decorates i386 names and, with -k, imports
            # stdcall functions by their undecorated name, as Windows' own
            # import libraries do.
            "$DLLTOOL" -m "$dllmachine" -k -d "$def" -l "$libs/$n.dll.lib" || return 1
        done
        # The libraries rustc names: msvcrt pulls in vcruntime and ucrt.
        for n in "$libs"/*.dll.lib; do
            local b
            b="$(basename "$n" .dll.lib)"
            [[ "$b" == msvcrt ]] && continue
            cp "$n" "$libs/$b.lib"
        done
        local crt=()
        for n in vcruntime140 ucrtbase; do [[ -f "$libs/$n.dll.lib" ]] && crt+=("$libs/$n.dll.lib"); done
        if [[ ${#crt[@]} -gt 0 ]]; then
            "$LIB" /out:"$libs/msvcrt.lib" "${crt[@]}"
        elif [[ -f "$libs/msvcrt.dll.lib" ]]; then
            cp "$libs/msvcrt.dll.lib" "$libs/msvcrt.lib"
        fi
        cp -f "$libs/vcruntime140.lib" "$libs/vcruntime.lib" 2> /dev/null
        cp -f "$libs/ucrtbase.lib" "$libs/ucrt.lib" 2> /dev/null
    done
    log "$out: link still failing after $i attempts:"
    grep -E 'error|undefined' <<< "$err" | head -20 >&2
    return 1
}

build_target() {
    local target="$1" machine="$2"
    if [[ ! -d "$SYSROOT/lib/rustlib/$target/lib" ]]; then
        log "skip $target: run 'rustup target add $target'"
        return 0
    fi
    local dir="$OUT/$target"
    mkdir -p "$dir"
    local crt="$WORK/crt-$target.obj" crtdll="$WORK/crtdll-$target.obj"
    "$RUSTC" --edition 2021 --target "$target" --crate-type=lib --emit=obj -C panic=abort -O \
        --check-cfg 'cfg(dll)' "$HERE/crt.rs" -o "$crt" || return 1
    "$RUSTC" --edition 2021 --target "$target" --crate-type=lib --emit=obj -C panic=abort -O \
        --check-cfg 'cfg(dll)' --cfg dll "$HERE/crt.rs" -o "$crtdll" || return 1
    # The dependency, as if unpacked by cargo on Windows.
    local reg='C:\Users\dev\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\fakedep-1.2.3\src'
    "$RUSTC" --edition 2021 --target "$target" --crate-type=rlib --crate-name fakedep -O \
        --remap-path-prefix "$HERE=$reg" "$HERE/fakedep.rs" -o "$WORK/libfakedep.rlib" || return 1
    local app='C:\Users\dev\winapp\src'
    local opt
    for opt in 0 2; do
        local exe="$dir/winapp-O$opt.exe"
        if [[ $FORCE == 0 && -f "$exe" && "$exe" -nt "$HERE/winapp.rs" && "$exe" -nt "$HERE/build.sh" ]]; then
            continue
        fi
        link_one "$target" "$machine" "$crt" "$exe" -C opt-level=$opt --crate-name winapp \
            --extern fakedep="$WORK/libfakedep.rlib" --remap-path-prefix "$HERE=$app" \
            "$HERE/winapp.rs" && log "built $exe"
    done
    # A DLL with exports that uses std.
    local dll="$dir/windll.dll"
    if [[ $FORCE == 1 || ! -f "$dll" || "$HERE/windll.rs" -nt "$dll" ]]; then
        link_one "$target" "$machine" "$crtdll" "$dll" -C opt-level=2 --crate-type cdylib \
            --crate-name windll --extern fakedep="$WORK/libfakedep.rlib" \
            --remap-path-prefix "$HERE=C:\\Users\\dev\\windll\\src" \
            "$HERE/windll.rs" && log "built $dll"
    fi
    rm -f "$dir"/*.rcgu.o "$dir"/*.lib "$dir"/*.exp
}

build_target x86_64-pc-windows-msvc x64
build_target i686-pc-windows-msvc x86
