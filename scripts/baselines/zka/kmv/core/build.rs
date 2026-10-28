// Passes KMV_K (number of minimum hash values kept; default 1024) to the crate as a compile-time constant.
use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=KMV_K");
    let k = env::var("KMV_K").unwrap_or_else(|_| "1024".to_string());
    let parsed: usize = k.trim().parse().expect("KMV_K must be a positive integer");
    assert!(parsed >= 2, "KMV_K must be at least 2");
    println!("cargo:rustc-env=KMV_K={}", parsed);
}
