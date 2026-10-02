// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `file` source's every fail-closed branch, with 1.5.5's texts (moved with the source from
//! busbar's `plugin-loader/src/builtin_secret.rs`).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// A process-unique temp path, so parallel tests never share one.
fn temp_path(tag: &str) -> std::path::PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "busbar-secret-file-t-{tag}-{}-{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst)
    ))
}

fn path(p: &std::path::Path) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("path".into(), p.to_string_lossy().into_owned().into());
    m
}

#[test]
fn a_file_resolves_byte_for_byte_untrimmed() {
    let p = temp_path("ok");
    std::fs::write(&p, b"file-secret\n").unwrap();
    assert_eq!(resolve(&path(&p)).unwrap(), b"file-secret\n");
    std::fs::write(&p, [0u8, 0xff, 0x10]).unwrap();
    assert_eq!(
        resolve(&path(&p)).unwrap(),
        [0u8, 0xff, 0x10],
        "binary keeps resolving"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn empty_and_blank_files_are_refused() {
    let p = temp_path("empty");
    std::fs::write(&p, b"").unwrap();
    let e = resolve(&path(&p)).unwrap_err();
    let d = p.display();
    assert_eq!(
        e.message,
        format!(
            "secret file:{d} resolved to an EMPTY file; a secret must be non-empty (fail-closed)"
        )
    );
    std::fs::write(&p, b" \n\t").unwrap();
    let e = resolve(&path(&p)).unwrap_err();
    assert!(
        e.message.contains("BLANK file (whitespace only)"),
        "{}",
        e.message
    );
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_missing_file_is_not_found_naming_the_path() {
    let p = temp_path("missing");
    let e = resolve(&path(&p)).unwrap_err();
    assert_eq!(error_kind(e.kind), ERROR_KIND_NOT_FOUND);
    assert!(
        e.message
            .starts_with(&format!("secret file:{} cannot resolve: ", p.display())),
        "{}",
        e.message
    );
}

#[test]
fn the_size_cap_is_exact_and_bounded() {
    let p = temp_path("cap");
    std::fs::write(&p, vec![b'a'; MAX_SECRET_FILE_BYTES as usize]).unwrap();
    assert_eq!(
        resolve(&path(&p)).unwrap().len() as u64,
        MAX_SECRET_FILE_BYTES
    );
    std::fs::write(&p, vec![b'a'; MAX_SECRET_FILE_BYTES as usize + 1]).unwrap();
    let e = resolve(&path(&p)).unwrap_err();
    assert!(
        e.message
            .ends_with("file exceeds the 1048576-byte secret size limit"),
        "{}",
        e.message
    );
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_directory_is_refused_as_not_a_regular_file() {
    let d = temp_path("dir");
    std::fs::create_dir_all(&d).unwrap();
    let e = resolve(&path(&d)).unwrap_err();
    assert!(
        e.message
            .contains("is not a regular file (it is a directory)"),
        "{}",
        e.message
    );
    let _ = std::fs::remove_dir(&d);
}

#[cfg(unix)]
#[test]
fn a_symlink_to_a_regular_file_still_resolves() {
    let (target, link) = (temp_path("target"), temp_path("link"));
    std::fs::write(&target, b"via-link").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(resolve(&path(&link)).unwrap(), b"via-link");
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn a_missing_or_blank_path_is_invalid() {
    let blank = |v: &str| {
        let mut m = serde_json::Map::new();
        m.insert("path".into(), v.into());
        m
    };
    for s in [serde_json::Map::new(), blank("  "), blank("\t\n")] {
        let e = resolve(&s).unwrap_err();
        assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
        assert_eq!(
            e.message,
            "secret module 'file' requires settings.path naming the file \
             (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)"
        );
    }
}

#[test]
fn settings_that_are_not_an_object_are_invalid() {
    assert!(settings_of(b"").unwrap().is_empty());
    let e = settings_of(b"[1]").unwrap_err();
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}
