fn main() {
    println!("cargo:rerun-if-changed=src/hook/filesystem/filesystem_shim.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/hook/filesystem/filesystem_shim.c")
            .warnings(true)
            .compile("agora_sandbox_filesystem_shim");
    }
}
