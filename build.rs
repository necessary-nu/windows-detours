fn main() {
    let mut build = cc::Build::new();

    build
        .cpp(true)
        .include("vendor/Detours/src")
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("_WIN32_WINNT", "0x0A00");

    // Always-compiled sources
    let always = &[
        "vendor/Detours/src/detours.cpp",
        "vendor/Detours/src/modules.cpp",
        "vendor/Detours/src/disasm.cpp",
        "vendor/Detours/src/image.cpp",
    ];
    for src in always {
        build.file(src);
    }

    // Process-creation support
    build.file("vendor/Detours/src/creatwth.cpp");

    // Architecture-specific disassemblers
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    match arch.as_str() {
        "x86_64" => {
            build.define("_AMD64_", None);
            build.file("vendor/Detours/src/disolx64.cpp");
            build.file("vendor/Detours/src/disolx86.cpp");
        }
        "x86" => {
            build.define("_X86_", None);
            build.file("vendor/Detours/src/disolx86.cpp");
        }
        "aarch64" => {
            build.define("_ARM64_", None);
            build.file("vendor/Detours/src/disolarm64.cpp");
            build.file("vendor/Detours/src/disolarm.cpp");
        }
        other => panic!("Unsupported target architecture: {other}"),
    }

    build.compile("detours");
}
