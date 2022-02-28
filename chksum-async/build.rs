use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTUP_TOOLCHAIN");

    let channel = match env::var("RUSTUP_TOOLCHAIN") {
        Ok(toolchain) => {
            let mut toolchain = toolchain.split('-');
            let channel = if let Some(channel) = toolchain.next() {
                channel
            } else {
                println!("cargo:warning=Cannot get channel, setting `nightly` by default.");
                "nightly"
            };
            channel.to_owned()
        },
        _ => "nightly".to_owned(),
    };
    println!("cargo:rustc-cfg={channel}");
}
