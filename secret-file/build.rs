// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Publish this source owner's refusal-scan test data without teaching the host its grammar.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .join("tests/source_scan_needles.json");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={}", file.display());
    println!("cargo::metadata=source_scan_needles={}", file.display());
    Ok(())
}
