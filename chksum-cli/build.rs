use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTUP_TOOLCHAIN");

    let channel = match env::var("RUSTUP_TOOLCHAIN") {
        Ok(toolchain) => {
            let mut toolchain = toolchain.split('-');
            let channel = match toolchain.next() {
                Some(channel @ ("stable" | "nightly")) => channel,
                Some(channel) => {
                    println!("cargo:warning=Cannot identify channel `{channel}`, setting `stable` by default.");
                    "stable"
                },
                None => {
                    println!("cargo:warning=Cannot get channel, setting `stable` by default.");
                    "stable"
                }
            };
            channel.to_owned()
        },
        _ => {
            println!("cargo:warning=Cannot get toolchain, setting `stable` by default.");
            "stable".to_owned()
        },
    };
    println!("cargo:rustc-cfg={channel}");
}
