fn main() {
    println!("cargo:rerun-if-changed=packaging/windows/pingrail.rc");
    println!("cargo:rerun-if-changed=packaging/windows/pingrail.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Icon and version information for pingrail.exe.
        embed_resource::compile("packaging/windows/pingrail.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("compiling Windows resources");
    }
}
