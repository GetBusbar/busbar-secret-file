// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Root source-resolution assertions transferred to the actual linked file owner.
//! Every resolution crosses SecretRows, the production dispatcher and the owner's SDK door.
use busbar_contract::{plugin::TestKernelSeal, redacted::Secret, secret::SecretAxis};
use busbar_plugin_loader::{
    dispatch::{DispatchConfig, Dispatcher},
    secret_calls::SecretRows,
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, OnceLock},
};

fn dispatcher() -> Arc<Dispatcher> {
    static ONE: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    ONE.get_or_init(|| {
        Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ))
    })
    .clone()
}
fn linked_axis() -> &'static SecretRows {
    static ONE: OnceLock<SecretRows> = OnceLock::new();
    ONE.get_or_init(|| {
        let mut rows = SecretRows::new(dispatcher, || None).with_disk_lane(|job| {
            job();
            Ok(())
        });
        rows.link(busbar_secret_file::door)
            .expect("the real owner door links");
        rows.declare_linked(busbar_secret_file::door, busbar_secret_file::DECLARES)
            .expect("the actual owner declaration reads");
        assert!(rows.linked("file"));
        rows
    })
}
fn reference(value: &str) -> serde_json::Map<String, serde_json::Value> {
    [("path".into(), value.into())].into_iter().collect()
}
fn resolve_linked(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<Secret<Vec<u8>>, String> {
    linked_axis()
        .shared("file")?
        .resolve_at_config(
            &serde_json::to_vec(settings).unwrap(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|error| error.text)
}
fn unique(tag: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "BUSBAR_ROOT_LINKED_TRANSFER_{tag}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}
fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(unique(tag))
}
fn resolve_on_a_request_path(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<Secret<Vec<u8>>, String> {
    linked_axis()
        .shared("file")?
        .resolve(&serde_json::to_vec(settings).unwrap())
        .map_err(|error| error.text)
}
#[test]
fn a_request_path_resolve_of_the_file_source_reads_nothing() {
    let path = temp_path("FILE_REQUEST_PATH");
    std::fs::write(&path, b"never-read-on-a-request-path").unwrap();
    let reference = reference(path.to_str().unwrap());
    let refused =
        resolve_on_a_request_path(&reference).expect_err("a request-path resolve is refused");
    assert!(
        refused.contains(busbar_contract::config_time::RESOLVE_OFF_CONFIG_TIME),
        "{refused}"
    );
    assert!(
        !refused.contains("never-read-on-a-request-path"),
        "{refused}"
    );
    let at_config = resolve_linked(&reference);
    assert_eq!(
        at_config
            .as_ref()
            .map(|value| value.expose(&TestKernelSeal).as_slice()),
        Ok(&b"never-read-on-a-request-path"[..])
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_happy_path_reads_the_file() {
    let path = temp_path("FILE_HAPPY");
    std::fs::write(&path, b"file-secret-bytes").unwrap();
    let got = resolve_linked(&reference(path.to_str().unwrap())).unwrap();
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got, b"file-secret-bytes");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_empty_file_is_fail_closed() {
    let path = temp_path("FILE_EMPTY");
    std::fs::write(&path, b"").unwrap();
    let err = resolve_linked(&reference(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("EMPTY"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_past_a_mebibyte_is_read_whole_as_1_5_5_did() {
    let path = temp_path("FILE_OVERSIZE");
    let oversize = vec![b'a'; 1024 * 1024 + 1];
    std::fs::write(&path, &oversize).unwrap();
    let got = resolve_linked(&reference(path.to_str().unwrap())).unwrap();
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got.len(), oversize.len());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_exactly_at_the_size_cap_still_resolves() {
    let path = temp_path("FILE_AT_CAP");
    let exact = vec![b'a'; 1024 * 1024];
    std::fs::write(&path, &exact).unwrap();
    let got = resolve_linked(&reference(path.to_str().unwrap())).unwrap();
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got.len(), 1024 * 1024);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING");
    let err = resolve_linked(&reference(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    assert!(
        !err.contains("regular file"),
        "a missing path is absent, not a wrong-file-type problem: {err}"
    );
}

#[test]
fn resolve_linked_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = serde_json::Map::new();
    let err = resolve_linked(&malformed).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
    assert!(!err.contains("is not a built-in"), "{err}");
}

#[test]
fn resolve_linked_file_blank_path_is_also_malformed() {
    let mut settings = serde_json::Map::new();
    settings.insert("path".to_string(), serde_json::Value::String("   ".into()));
    let blank = settings;
    let err = resolve_linked(&blank).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
}

#[test]
fn file_whitespace_only_path_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let err = resolve_linked(&reference(bad)).expect_err(&format!(
            "whitespace-only file path {bad:?} must be rejected"
        ));
        assert!(
            err.contains("requires settings.path"),
            "whitespace-only file path {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

#[test]
fn resolve_linked_file_directory_is_refused_as_not_a_regular_file() {
    let dir = temp_path("FILE_IS_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let err = resolve_linked(&reference(dir.to_str().unwrap()))
        .expect_err("a directory is not a readable secret");
    assert!(
        err.contains("regular file"),
        "the refusal must name the real problem — that the path is not a regular file: {err}"
    );
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(unix)]
#[test]
fn resolve_linked_file_symlink_to_a_regular_file_still_resolves() {
    let target = temp_path("FILE_SYMLINK_TARGET");
    std::fs::write(&target, b"symlinked-secret").unwrap();
    let link = temp_path("FILE_SYMLINK_LINK");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let got = resolve_linked(&reference(link.to_str().unwrap()))
        .expect("a symlink to a regular file is how Kubernetes mounts a secret");
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got, b"symlinked-secret");
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn resolve_linked_file_whitespace_only_content_resolves_as_1_5_5_did() {
    for blank in [b"   ".to_vec(), b"\n\r\n".to_vec(), b"\t \n".to_vec()] {
        let path = temp_path("FILE_BLANK");
        std::fs::write(&path, &blank).unwrap();
        let got = resolve_linked(&reference(path.to_str().unwrap()))
            .unwrap_or_else(|e| panic!("whitespace-only file {blank:?} resolves as in 1.5.5: {e}"));
        let got = got.expose(&TestKernelSeal).as_slice();
        assert_eq!(got, blank, "its bytes, untouched");
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn resolve_linked_file_real_content_still_resolves_including_binary() {
    let padded = temp_path("FILE_PADDED");
    std::fs::write(&padded, b"  pem-body\n").unwrap();
    let got = resolve_linked(&reference(padded.to_str().unwrap())).unwrap();
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got, b"  pem-body\n", "a real credential is never trimmed");
    let _ = std::fs::remove_file(&padded);

    let binary = temp_path("FILE_BINARY");
    std::fs::write(&binary, [0x00u8, 0xFF, 0x10, 0x80]).unwrap();
    let got = resolve_linked(&reference(binary.to_str().unwrap()))
        .expect("a binary (non-UTF-8) secret is legitimate on the raw-bytes path");
    let got = got.expose(&TestKernelSeal).as_slice();
    assert_eq!(got, vec![0x00u8, 0xFF, 0x10, 0x80]);
    let _ = std::fs::remove_file(&binary);
}
