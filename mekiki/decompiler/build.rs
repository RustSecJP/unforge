// Compiles the vendored Ghidra decompiler (ghidra/*.cc) and our driver
// (src/mekiki_decomp.cc) into one static library linked into the binary.
fn main() {
    let mut files: Vec<_> = std::fs::read_dir("ghidra")
        .expect("ghidra/ sources")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "cc"))
        .collect();
    files.sort();
    files.push("src/mekiki_decomp.cc".into());
    files.push("src/printrust.cc".into());
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .include("ghidra")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-deprecated-copy")
        .warnings(false)
        .files(&files);
    // The zlib library's name differs between builds (zlib 1.4 static: zs.lib).
    let mut zlib = if msvc { "zlib" } else { "z" }.to_owned();
    if msvc {
        // Ghidra's own Windows build: _WINDOWS picks the Win32 file APIs.
        // zlib: ZLIB_ROOT/include and ZLIB_ROOT/lib (vcpkg in CI; see release.yml).
        build.define("_WINDOWS", None).define("WIN64", None).flag("/EHsc").flag("/bigobj");
        if let Ok(root) = std::env::var("ZLIB_ROOT") {
            let root = std::path::Path::new(&root);
            build.include(root.join("include"));
            println!("cargo:rustc-link-search=native={}", root.join("lib").display());
            // Any z*.lib in the folder (zlib.lib, zs.lib, zlibstatic.lib, ...).
            let found = std::fs::read_dir(root.join("lib")).into_iter().flatten().flatten().find_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let stem = name.strip_suffix(".lib")?;
                (stem.starts_with('z') && !stem.ends_with('d')).then(|| stem.to_owned())
            });
            if let Some(n) = found {
                zlib = n;
            }
        }
    }
    println!("cargo:rerun-if-env-changed=ZLIB_ROOT");
    build.compile("ghidra_decomp");
    println!("cargo:rustc-link-lib={zlib}");
    println!("cargo:rerun-if-changed=ghidra");
    println!("cargo:rerun-if-changed=src");
}
