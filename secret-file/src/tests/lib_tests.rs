// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `file` source's every fail-closed branch, with 1.5.5's texts (moved with the source from
//! busbar's `plugin-loader/src/builtin_secret.rs`).

use super::*;
use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
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

/// AS 1.5.5 (`crates/busbar/src/config/secret.rs` `resolve_builtin`): an EMPTY file is refused, and
/// a whitespace-only one RESOLVES, its bytes untouched. 1.5.5 tested a file only for emptiness;
/// refusing a blank one is a behaviour difference no owner has signed (THE DESIGN §2: the default
/// is 1.5.5's behaviour). RED before the restore: the blank file was refused.
#[test]
fn an_empty_file_is_refused_and_a_blank_one_resolves_as_in_1_5_5() {
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
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    std::fs::write(&p, b" \n\t").unwrap();
    assert_eq!(
        resolve(&path(&p)).expect("a blank file resolves, as in 1.5.5"),
        b" \n\t"
    );
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

/// RED (audit pinned secret-file #2): PARITY WITH 1.5.5, which read a `file:` secret whole
/// (`std::fs::read`, v1.5.5 `crates/busbar/src/config/secret.rs` `resolve_builtin`): a file of
/// several MiB (a large PEM bundle) resolves byte for byte, never refused for its size.
#[test]
fn a_large_file_resolves_whole_as_1_5_5_read_it() {
    let p = temp_path("large");
    let large: Vec<u8> = (0..3 * 1024 * 1024 + 7)
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    std::fs::write(&p, &large).unwrap();
    assert_eq!(resolve(&path(&p)).unwrap(), large);
    let _ = std::fs::remove_file(&p);
}

/// The refusal a source above the secret kind's answer bound reads as: the path, never the content.
fn over_bound(p: &str) -> String {
    format!(
        "secret file:{p} cannot resolve: the file is larger than {HARD_MAX_BYTES} bytes, the most \
         a secret may hold (fail-closed)"
    )
}

/// RED (row 159, audit A MEDIUM): a regular file above the secret kind's answer bound
/// (`HARD_MAX_BYTES`, busbar-contract `abi/mechanism/check.rs`) is REFUSED, naming the path, before
/// a byte is read or leased. Answered READY, the host's answer check turns it into a bare FAULT
/// naming neither path nor cause, and the lease is never released. RED before the fix: it resolved.
#[test]
fn a_file_above_the_answer_bound_is_refused_naming_the_path() {
    let p = temp_path("over");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(HARD_MAX_BYTES + 1).unwrap();
    drop(f);
    let e = resolve(&path(&p)).unwrap_err();
    std::fs::remove_file(&p).ok();
    assert_eq!(e.message, over_bound(&p.display().to_string()));
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

/// NEGATIVE CONTROL for the bound: a file of exactly `HARD_MAX_BYTES` resolves whole, as 1.5.5
/// read it.
#[test]
fn a_file_at_the_answer_bound_resolves_whole() {
    let p = temp_path("at-bound");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(HARD_MAX_BYTES).unwrap();
    drop(f);
    let got = resolve(&path(&p));
    std::fs::remove_file(&p).ok();
    let got = got.expect("a file at the bound resolves");
    assert_eq!(got.len() as u64, HARD_MAX_BYTES);
    assert!(got.iter().all(|&b| b == 0));
}

/// RED (row 159, audit A MEDIUM): a source with no length up front (a device that never ends) is
/// refused at the bound, naming the path, never read past it. RED before the fix: `/dev/zero` was
/// refused as not a regular file, text 1.5.5 never gave.
#[cfg(unix)]
#[test]
fn a_stream_past_the_answer_bound_is_refused_naming_the_path() {
    let e = resolve(&path(std::path::Path::new("/dev/zero"))).unwrap_err();
    assert_eq!(e.message, over_bound("/dev/zero"));
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

/// RED (row 159, audits A HIGH / B MEDIUM): AS 1.5.5 (`std::fs::read`, v1.5.5
/// `crates/busbar/src/config/secret.rs` `resolve_builtin`), a fifo is read once a writer supplies
/// it: a secret delivered over a named pipe, a piped `/dev/stdin` or a `<(cmd)` path resolves. No
/// owner-signed accepted difference refuses it. RED before the fix: refused as not a regular file.
#[cfg(unix)]
#[test]
fn a_fifo_with_a_writer_resolves_as_1_5_5_read_it() {
    let fifo = temp_path("fifo");
    let _ = std::fs::remove_file(&fifo);
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo made the fifo");
    let to = fifo.clone();
    std::thread::spawn(move || {
        use std::io::Write;
        let mut w = std::fs::OpenOptions::new().write(true).open(&to).unwrap();
        let _ = w.write_all(b"piped-secret\n");
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let at = path(&fifo);
    std::thread::spawn(move || {
        let _ = tx.send(resolve(&at));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(20));
    let _ = std::fs::remove_file(&fifo);
    let got = answered.expect("the read answered once the writer closed");
    assert_eq!(
        got.map_err(|e| e.message).as_deref(),
        Ok(&b"piped-secret\n"[..])
    );
}

/// RED (row 159, audits A HIGH / B MEDIUM): a directory is refused in 1.5.5's words, byte for
/// byte: `secret file:{path} cannot resolve: {io_error}`, the error `std::fs::read` gave (1.5.5
/// inventory `qa/evidence/inventory/1.5.5-auth-secrets.md`, the `file` read-error row). RED before
/// the fix: it read `... is not a regular file (it is a directory) ...`.
#[test]
fn a_directory_is_refused_in_1_5_5_s_words() {
    let d = temp_path("dir");
    std::fs::create_dir_all(&d).unwrap();
    let e = resolve(&path(&d)).unwrap_err();
    let read = std::fs::read(&d).expect_err("1.5.5's read of a directory fails");
    let _ = std::fs::remove_dir(&d);
    assert_eq!(
        e.message,
        format!("secret file:{} cannot resolve: {read}", d.display())
    );
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

/// RED (row 159, audit A HIGH): `/dev/null` reads as 1.5.5 read it, an EMPTY file, refused in
/// 1.5.5's empty-file words. RED before the fix: refused as not a regular file.
#[cfg(unix)]
#[test]
fn dev_null_is_refused_as_1_5_5_s_empty_file() {
    let e = resolve(&path(std::path::Path::new("/dev/null"))).unwrap_err();
    assert_eq!(
        e.message,
        "secret file:/dev/null resolved to an EMPTY file; a secret must be non-empty (fail-closed)"
    );
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
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

/// R4 (busbar `BUSBAR-1.6.0.md` l.1464-1469): the file source reads the disk, and says so in its
/// `declares`, so the host resolves it only at config time on its disk lane. RED ARM: the section
/// stated only its contract range, and the host resolved this source on a request path.
#[test]
fn the_declares_section_states_the_disk_need() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).expect("declares.json is JSON");
    assert_eq!(d["disk"], serde_json::Value::Bool(true), "{DECLARES}");
}

/// A PATH THE OPERATOR GOT WRONG IS A CONFIG ERROR, A FILESYSTEM THAT CANNOT BE REACHED IS AN
/// OUTAGE (App. A B.2; the contract's taxonomy: `ERROR_KIND_INVALID` is settings that are wrong,
/// `ERROR_KIND_UNAVAILABLE` a backend, the filesystem included, that could not be reached): a path
/// through a regular file, a symlink loop, a directory, an over-long or NUL-bearing name, a socket
/// read as `Invalid`; a failing disk (`EIO`), memory the read could not get, and any other cause
/// read as `Unavailable`. RED (row 159, audit B LOW) before the fix: `EIO` and out-of-memory read
/// as `Invalid`, a config error the operator cannot fix.
#[test]
fn an_io_error_is_classified_config_or_unreachable_by_its_kind() {
    use std::io::{Error, ErrorKind};
    let mut config = vec![
        Error::from(ErrorKind::NotADirectory),
        Error::from(ErrorKind::IsADirectory),
        Error::from(ErrorKind::InvalidFilename),
        Error::from(ErrorKind::InvalidInput),
        Error::from(ErrorKind::Unsupported),
    ];
    let mut unreachable = vec![
        Error::from(ErrorKind::Interrupted),
        Error::from(ErrorKind::TimedOut),
        Error::from(ErrorKind::WouldBlock),
        Error::from(ErrorKind::ResourceBusy),
        Error::from(ErrorKind::StaleNetworkFileHandle),
        Error::from(ErrorKind::OutOfMemory),
    ];
    #[cfg(unix)]
    {
        config.push(Error::from_raw_os_error(libc::ELOOP));
        config.push(Error::from_raw_os_error(libc::ENXIO));
        unreachable.push(Error::from_raw_os_error(libc::EIO));
    }
    for e in &config {
        assert_eq!(io_refusal("/p", e).kind, SecretErrorKind::Invalid, "{e:?}");
    }
    for e in &unreachable {
        assert_eq!(
            io_refusal("/p", e).kind,
            SecretErrorKind::Unavailable,
            "{e:?}"
        );
    }
    assert_eq!(
        io_refusal("/p", &Error::from(ErrorKind::NotFound)).kind,
        SecretErrorKind::NotFound
    );
    assert_eq!(
        io_refusal("/p", &Error::from(ErrorKind::PermissionDenied)).kind,
        SecretErrorKind::Denied
    );
}

/// A file whose reported length no allocation can hold (a sparse 8 TiB file) is refused at the
/// answer bound, naming the path, before any buffer is sized from its length; it never aborts the
/// process (Q128 secret-file, reader B on fcf42d8: the buffer was once pre-sized infallibly from the
/// length, and the test process aborted).
#[cfg(target_os = "linux")]
#[test]
fn a_length_no_allocation_can_hold_is_refused_not_an_abort() {
    let at = temp_path("huge");
    let file = std::fs::File::create(&at).unwrap();
    file.set_len(1 << 43).expect("a sparse file of that length");
    drop(file);
    let e = resolve(&path(&at)).unwrap_err();
    std::fs::remove_file(&at).ok();
    assert_eq!(e.message, over_bound(&at.display().to_string()));
}
