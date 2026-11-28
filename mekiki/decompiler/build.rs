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
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .include("ghidra")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-deprecated-copy")
        .warnings(false)
        .files(&files)
        .compile("ghidra_decomp");
    println!("cargo:rustc-link-lib=z");
    println!("cargo:rerun-if-changed=ghidra");
    println!("cargo:rerun-if-changed=src");
}
