// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::distribution::config_validation_application::{
    make_provider, make_root_cfg, proto_a, validate,
};
use busbar_kernel::config;
use std::collections::HashMap;

#[test]
fn test_validate_rejects_empty_canonical_file_secret_ref() {
    let empty_file: config::SecretRef =
        serde_yaml::from_str("{ module: file, settings: { path: \"\" } }")
            .expect("canonical empty-path file ref deserializes");
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.acme.example.com", "IGNORED");
    p.api_key = empty_file;
    providers.insert("acme".to_string(), p);
    let errs = validate(&make_root_cfg(providers, HashMap::new(), HashMap::new()))
        .expect_err("an empty canonical file path must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("providers.acme.api_key")
            && e.contains("'file'")
            && e.to_lowercase().contains("non-empty")),
        "expected a non-empty settings.path error naming providers.acme.api_key; got: {errs:?}"
    );
}
