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
    assert!(resolve(&path(&p)).expect("resolves") == Held::new(b"file-secret\n".to_vec()));
    std::fs::write(&p, [0u8, 0xff, 0x10]).unwrap();
    assert!(
        resolve(&path(&p)).expect("resolves") == Held::new(vec![0u8, 0xff, 0x10]),
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
    let e = resolve(&path(&p)).err().expect("refused");
    let d = p.display();
    assert_eq!(
        e.message,
        format!(
            "secret file:{d} resolved to an EMPTY file; a secret must be non-empty (fail-closed)"
        )
    );
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    std::fs::write(&p, b" \n\t").unwrap();
    assert!(
        resolve(&path(&p)).expect("a blank file resolves, as in 1.5.5")
            == Held::new(b" \n\t".to_vec())
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_missing_file_is_not_found_naming_the_path() {
    let p = temp_path("missing");
    let e = resolve(&path(&p)).err().expect("refused");
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
    assert!(resolve(&path(&p)).expect("resolves") == Held::new(large));
    let _ = std::fs::remove_file(&p);
}

/// RED (audit pinned secret-file #3): a device node (`/dev/zero`, which never ends) is refused in
/// the registered words and never read. This pins the refusal and its text only: a check of the
/// path before the open would refuse it alike, so it does not by itself prove the type is judged
/// on the OPENED handle (no test here swaps a path between a check and the open).
#[cfg(unix)]
#[test]
fn a_device_node_is_refused_and_never_read() {
    let e = read_file("/dev/zero").err().expect("refused");
    assert_eq!(
        e.to_string(),
        "the path is not a regular file (it is a device node or fifo); a `file:` \
         secret must name a regular file holding the credential bytes (fail-closed)"
    );
    assert_eq!(e.kind(), std::io::ErrorKind::Other);
}

/// RED (Q128 secret-file LOW): the open itself never blocks on a fifo. The handle is opened
/// non-blocking and its type judged on the handle, so a path that is a fifo when it is opened (one
/// swapped in after any path check) is refused at once, never waited on for a writer. RED before
/// the fix: `read_file` opened the fifo blocking and hung until a writer appeared.
#[cfg(unix)]
#[test]
fn a_fifo_is_refused_at_once_never_waited_on() {
    let fifo = temp_path("fifo");
    let _ = std::fs::remove_file(&fifo);
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo made the fifo");
    let (tx, rx) = std::sync::mpsc::channel();
    let at = fifo.clone();
    std::thread::spawn(move || {
        let _ = tx.send(read_file(at.to_str().unwrap()).map(|_| ()));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(5));
    let _ = std::fs::remove_file(&fifo);
    let e = answered
        .expect("the open answered without waiting for a writer")
        .expect_err("a fifo is refused");
    assert!(e.to_string().contains("is not a regular file"), "{e}");
}

#[test]
fn a_directory_is_refused_as_not_a_regular_file() {
    let d = temp_path("dir");
    std::fs::create_dir_all(&d).unwrap();
    let e = resolve(&path(&d)).err().expect("refused");
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
    assert!(resolve(&path(&link)).expect("resolves") == Held::new(b"via-link".to_vec()));
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
        let e = resolve(&s).err().expect("refused");
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

/// A PATH THE OPERATOR GOT WRONG IS A CONFIG ERROR, NOT AN OUTAGE (App. A B.2; the contract's
/// `SecretErrorKind` taxonomy): a path through a regular file, a symlink loop, a directory, an
/// over-long or NUL-bearing name read as `Invalid`; only a transient I/O failure is `Unavailable`,
/// and anything else defaults to the config kind. A symlink loop's kind (`FilesystemLoop`) is not
/// stable on the pinned toolchain, so it is not named here; it falls to that same default. RED
/// before the fix: every error that was not not-found or permission-denied read as an outage.
/// RED before the fix: a network outage (`NetworkDown`, `NetworkUnreachable`, `HostUnreachable`,
/// `ConnectionReset`, `ConnectionAborted`, `NotConnected`) or descriptor exhaustion (`EMFILE`,
/// `ENFILE`) reading the file read as a config error ("the settings blob is malformed").
#[test]
fn an_io_error_is_classified_config_or_transient_by_its_kind() {
    use std::io::{Error, ErrorKind};
    for kind in [
        ErrorKind::NotADirectory,
        ErrorKind::IsADirectory,
        ErrorKind::InvalidFilename,
        ErrorKind::InvalidInput,
        ErrorKind::Unsupported,
    ] {
        assert_eq!(
            io_refusal("/p", &Error::from(kind)).kind,
            SecretErrorKind::Invalid,
            "{kind:?}"
        );
    }
    for kind in [
        ErrorKind::Interrupted,
        ErrorKind::TimedOut,
        ErrorKind::WouldBlock,
        ErrorKind::ResourceBusy,
        ErrorKind::StaleNetworkFileHandle,
        ErrorKind::NetworkDown,
        ErrorKind::NetworkUnreachable,
        ErrorKind::HostUnreachable,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::NotConnected,
    ] {
        assert_eq!(
            io_refusal("/p", &Error::from(kind)).kind,
            SecretErrorKind::Unavailable,
            "{kind:?}"
        );
    }
    #[cfg(unix)]
    {
        for errno in [libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                io_refusal("/p", &Error::from_raw_os_error(errno)).kind,
                SecretErrorKind::Unavailable,
                "errno {errno}"
            );
        }
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

/// RED (Q128 secret-file, reader B on fcf42d8): a file whose reported length no allocation can
/// hold (a sparse 8 TiB file, past any CI host under Linux's default overcommit heuristic) is
/// REFUSED with the allocator's out-of-memory error, as 1.5.5's `std::fs::read` refused it through
/// its fallible reservation; it never aborts the process. RED before the fix: the buffer was
/// pre-sized infallibly from the length, and the test process aborted.
#[cfg(target_os = "linux")]
#[test]
fn a_length_no_allocation_can_hold_is_refused_not_an_abort() {
    let at = temp_path("huge");
    let file = std::fs::File::create(&at).unwrap();
    file.set_len(1 << 43).expect("a sparse file of that length");
    drop(file);
    let e = read_file(at.to_str().unwrap()).err().expect("refused");
    std::fs::remove_file(&at).ok();
    assert_eq!(e.kind(), std::io::ErrorKind::OutOfMemory, "{e}");
}

/// RED (codeaudit secret-file #2): a regular file whose `fstat` length UNDER-STATES its content (a
/// procfs file states 0, as a file growing mid-read outruns its length) resolves whole: the read
/// outgrows the buffer sized from the length more than once, and every byte read before a growth
/// is carried into the larger buffer. Read off a child whose command line is known byte for byte.
/// RED with the carry (`bigger.extend_from_slice(&buf)`) removed: the bytes read before the second
/// growth were lost, and the secret came back truncated with no error.
#[cfg(target_os = "linux")]
#[test]
fn a_file_longer_than_its_stated_length_resolves_whole() {
    let long = "x".repeat(40 * 1024);
    let argv = ["/bin/sh", "-c", "while :; do sleep 1; done", "sh", &long];
    let mut expected = Vec::new();
    for arg in argv {
        expected.extend_from_slice(arg.as_bytes());
        expected.push(0);
    }
    let mut child = std::process::Command::new(argv[0])
        .args(&argv[1..])
        .spawn()
        .expect("sh runs");
    let at = std::path::PathBuf::from(format!("/proc/{}/cmdline", child.id()));
    // The child's argv is in place only once its exec has set it up (`spawn` returns as the exec
    // begins); until then its cmdline reads empty.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::fs::read(&at).map_or(true, |b| b != expected) && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let stated = std::fs::metadata(&at).map(|m| (m.is_file(), m.len()));
    let read = resolve(&path(&at));
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        stated.expect("the child's cmdline"),
        (true, 0),
        "a regular file stating length 0"
    );
    let read = read.expect("the cmdline resolves");
    assert_eq!(
        read.len(),
        expected.len(),
        "resolved whole, nothing dropped"
    );
    assert!(read == Held::new(expected), "resolved byte for byte");
}

/// The refusal names the path ONCE (before `cannot resolve: `), not again in the cause (sibling
/// review 2026-10-25).
#[test]
fn a_non_regular_file_refusal_names_the_path_once() {
    let d = temp_path("dir-once");
    std::fs::create_dir_all(&d).unwrap();
    let e = resolve(&path(&d)).err().expect("refused");
    let _ = std::fs::remove_dir(&d);
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    assert_eq!(
        e.message.matches(d.to_str().unwrap()).count(),
        1,
        "{}",
        e.message
    );
}

/// A reference names its file and nothing else: any other setting (a typo, a key meant for another
/// source) is refused naming it, rather than ignored (sibling review 2026-10-25).
#[test]
fn a_reference_naming_another_setting_is_invalid_naming_it() {
    let p = temp_path("extra");
    std::fs::write(&p, b"v").unwrap();
    let mut s = path(&p);
    s.insert("key".into(), "X".into());
    let e = resolve(&s).err().expect("refused");
    let _ = std::fs::remove_file(&p);
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    assert_eq!(
        e.message,
        "secret module 'file' does not take settings.key; a reference names only settings.path \
         (fail-closed)"
    );
}

/// The source takes no instance settings: none or an empty object opens it, and a setting is
/// refused naming it (not ignored), as are bytes that are not a JSON object.
#[test]
fn instance_settings_are_none_and_a_setting_is_refused_naming_it() {
    assert_eq!(instance_settings(b""), Ok(()));
    assert_eq!(instance_settings(b"{}"), Ok(()));
    assert_eq!(
        instance_settings(br#"{"path":"/x"}"#),
        Err(
            "secret module 'file' takes no settings; remove settings.path (each reference \
             names its file in its own settings.path)"
                .to_string()
        )
    );
    for bad in [&b"[1]"[..], b"null", b"\"x\"", b"{"] {
        assert_eq!(
            instance_settings(bad),
            Err("settings: must be a JSON object".to_string()),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}
