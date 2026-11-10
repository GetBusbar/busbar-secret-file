// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `file` source's every fail-closed branch, with 1.5.5's texts (moved with the source from
//! busbar's `plugin-loader/src/builtin_secret.rs`).

use super::*;
use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
use busbar_contract::abi::sdk::secret::{error_kind, settings_of, takes_no_settings};
use busbar_contract::abi::secret::{ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND};
use std::sync::atomic::{AtomicU64, Ordering};

/// The instance settings as the door judges them (`validate`, `open`, `refresh`).
fn instance_settings(bytes: &[u8]) -> Result<(), String> {
    takes_no_settings(bytes, WORD, NAMES)
}

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
/// a whitespace-only one RESOLVES, its bytes untouched.
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

#[cfg(unix)]
#[test]
fn a_device_node_is_refused_and_never_read() {
    let e = read_file("/dev/zero", |_| ()).err().expect("refused");
    assert_eq!(
        e.message,
        "secret file:/dev/zero cannot resolve: the path is not a regular file (it is a device \
         node or fifo); a `file:` secret must name a regular file holding the credential bytes \
         (fail-closed)"
    );
    assert_eq!(e.kind, SecretErrorKind::Invalid);
}

/// The refusal a file above the secret kind's answer bound reads as: the path, never the content.
fn over_bound_text(p: &str) -> String {
    format!(
        "secret file:{p} cannot resolve: the file is larger than {HARD_MAX_BYTES} bytes, the most \
         a secret may hold (fail-closed)"
    )
}

#[test]
fn a_file_above_the_answer_bound_is_refused_naming_the_path() {
    let p = temp_path("over");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(HARD_MAX_BYTES + 1).unwrap();
    drop(f);
    let e = resolve(&path(&p)).err().expect("refused");
    std::fs::remove_file(&p).ok();
    assert_eq!(e.message, over_bound_text(&p.display().to_string()));
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

/// NEGATIVE CONTROL for the bound: a file of exactly `HARD_MAX_BYTES` resolves whole.
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
    assert!(
        got == Held::new(vec![0_u8; got.len()]),
        "the file's bytes, whole"
    );
}

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
        let _ = tx.send(read_file(at.to_str().unwrap(), |_| ()).map(|_| ()));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(5));
    let _ = std::fs::remove_file(&fifo);
    let e = answered
        .expect("the open answered without waiting for a writer")
        .expect_err("a fifo is refused");
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert!(
        e.message
            .contains("is not a regular file (it is a device node or fifo)"),
        "{}",
        e.message
    );
}

#[test]
fn a_directory_is_refused_as_not_a_regular_file() {
    let d = temp_path("dir");
    std::fs::create_dir_all(&d).unwrap();
    let e = resolve(&path(&d)).err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Invalid);
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

#[test]
fn the_declares_section_states_the_disk_need() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).expect("declares.json is JSON");
    assert_eq!(d["disk"], serde_json::Value::Bool(true), "{DECLARES}");
}

/// A PATH THE OPERATOR GOT WRONG IS A CONFIG ERROR, NOT AN OUTAGE (App. A B.2; the contract's
/// `SecretErrorKind` taxonomy): a path through a regular file, a directory, an over-long or
/// NUL-bearing name read as `Invalid`; only a transient I/O failure is `Unavailable`, and anything
/// else defaults to the config kind.
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
        ErrorKind::OutOfMemory,
    ] {
        assert_eq!(
            io_refusal("/p", &Error::from(kind)).kind,
            SecretErrorKind::Unavailable,
            "{kind:?}"
        );
    }
    #[cfg(unix)]
    {
        for errno in [libc::EMFILE, libc::ENFILE, libc::EIO] {
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

/// A file whose reported length no allocation can hold (a sparse 8 TiB file) is refused at the
/// answer bound, naming the path, before any buffer is sized from its length; it never aborts.
#[cfg(target_os = "linux")]
#[test]
fn a_length_no_allocation_can_hold_is_refused_not_an_abort() {
    let at = temp_path("huge");
    let file = std::fs::File::create(&at).unwrap();
    file.set_len(1 << 43).expect("a sparse file of that length");
    drop(file);
    let e = resolve(&path(&at)).err().expect("refused");
    std::fs::remove_file(&at).ok();
    assert_eq!(e.message, over_bound_text(&at.display().to_string()));
}

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
/// source) is refused INVALID, naming it.
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

/// A misspelled key with no `path` at all is named in the refusal, not hidden behind the generic
/// missing-path text.
#[test]
fn a_misspelled_path_key_is_named_in_the_refusal() {
    let mut s = serde_json::Map::new();
    s.insert("paht".into(), "/x".into());
    let e = resolve(&s).err().expect("refused");
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    assert!(e.message.contains("settings.paht"), "{}", e.message);
}

/// The source takes no instance settings: none or an empty object opens it, and a setting is
/// refused naming it.
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
    for bad in [&b"[1]"[..], b"null", b"\"x\""] {
        assert_eq!(
            instance_settings(bad),
            Err("settings: must be a JSON object".to_string()),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        instance_settings(b"{"),
        Err("settings: EOF while parsing an object at line 1 column 1".to_string())
    );
}

/// Root opens anything, so a 0o000 path would not be denied. `libc::geteuid` is unsafe and this
/// crate forbids unsafe, so read the effective uid off the owner of a file just created.
#[cfg(unix)]
fn running_as_root() -> bool {
    let probe = temp_path("euid-probe");
    std::fs::write(&probe, b"x").unwrap();
    let root = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&probe).unwrap()) == 0;
    let _ = std::fs::remove_file(&probe);
    root
}

/// RED (codeaudit secret-file LOW): a directory the process may not open is refused as a
/// directory (INVALID, the not-regular text), not as a bare DENIED "Permission denied" that never
/// says the operator pointed the credential at a folder. (On Windows every directory open fails
/// this way.) RED before the fix: it answered DENIED. It runs as root too (root opens the
/// directory, and the answer is the same), so it is never a silent pass.
#[cfg(unix)]
#[test]
fn an_unopenable_directory_is_refused_as_a_directory() {
    use std::os::unix::fs::PermissionsExt;
    let d = temp_path("dir-denied");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
    let e = resolve(&path(&d));
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir(&d);
    let e = e.err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Invalid, "{}", e.message);
    assert!(
        e.message
            .contains("is not a regular file (it is a directory)"),
        "{}",
        e.message
    );
}

/// An unreadable regular file is refused as DENIED with the std error text, not as a
/// not-a-regular-file INVALID (that wording is for directories, devices and fifos).
#[cfg(unix)]
#[test]
fn an_unreadable_regular_file_is_refused_as_denied() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        return;
    }
    let f = temp_path("file-denied");
    std::fs::write(&f, b"s3cret").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied = std::fs::File::open(&f).expect_err("0o000 is unreadable");
    let e = resolve(&path(&f));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let _ = std::fs::remove_file(&f);
    let e = e.err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Denied, "{}", e.message);
    assert_eq!(
        e.message,
        format!("secret file:{} cannot resolve: {denied}", f.display())
    );
}

/// A reader that is interrupted once before each chunk it yields, as an EINTR during `read(2)`.
struct Interrupting {
    data: &'static [u8],
    interrupt_next: bool,
}

impl std::io::Read for Interrupting {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        self.interrupt_next = true;
        let n = self.data.len().min(out.len()).min(3);
        out[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// An interrupted read is retried: the secret resolves whole, byte for byte.
#[test]
fn an_interrupted_read_is_retried_and_resolves_whole() {
    let mut r = Interrupting {
        data: b"interrupted-secret",
        interrupt_next: true,
    };
    let got = read_bounded(&mut r, 0, "/p/eintr", |_| ()).expect("resolves");
    assert!(got == Held::new(b"interrupted-secret".to_vec()));
}

/// A reader yielding `left` copies of one byte, in whatever sizes it is asked for, then either the
/// end or an I/O error.
struct Repeat {
    left: usize,
    byte: u8,
    then_err: bool,
}

impl std::io::Read for Repeat {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return if self.then_err {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            } else {
                Ok(0)
            };
        }
        let n = self.left.min(out.len());
        out[..n].fill(self.byte);
        self.left -= n;
        Ok(n)
    }
}

/// The mid-read bound: a reader that outruns a stated length of 0 is refused one byte past MAX,
/// naming the path.
#[test]
fn a_reader_past_the_bound_mid_read_is_refused_naming_the_path() {
    let mut r = Repeat {
        left: MAX + 1,
        byte: b'z',
        then_err: false,
    };
    let e = read_bounded(&mut r, 0, "/p/over", |_| ())
        .err()
        .expect("refused");
    assert_eq!(e.message, over_bound_text("/p/over"));
    assert_eq!(e.kind, SecretErrorKind::Invalid);
}

/// NEGATIVE CONTROL for the mid-read bound: exactly MAX bytes against a stated length of 0
/// resolves whole.
#[test]
fn a_reader_at_the_bound_mid_read_resolves_whole() {
    let mut r = Repeat {
        left: MAX,
        byte: b'q',
        then_err: false,
    };
    let got = read_bounded(&mut r, 0, "/p/at", |_| ()).expect("resolves");
    assert_eq!(got.len(), MAX);
    assert!(got == Held::new(vec![b'q'; MAX]));
}

/// An I/O error after some bytes is refused with the io text, kind by [`io_refusal`].
#[test]
fn a_reader_failing_mid_read_is_refused_with_the_io_text() {
    let mut r = Repeat {
        left: 20_000,
        byte: b'e',
        then_err: true,
    };
    let e = read_bounded(&mut r, 0, "/p/err", |_| ())
        .err()
        .expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    assert_eq!(
        e.message,
        format!(
            "secret file:/p/err cannot resolve: {}",
            std::io::Error::from(std::io::ErrorKind::TimedOut)
        )
    );
}

/// A stated length smaller than the data forces the growth branch; every byte survives it.
#[test]
fn a_reader_longer_than_its_hint_grows_and_resolves_whole() {
    let data: Vec<u8> = (0..100_000_u32).map(|i| (i % 251) as u8).collect();
    struct Slice<'a>(&'a [u8]);
    impl std::io::Read for Slice<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.len().min(out.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let got = read_bounded(&mut Slice(&data), 10, "/p/grow", |_| ()).expect("resolves");
    assert_eq!(got.len(), data.len());
    assert!(got == Held::new(data));
}

#[test]
fn an_extra_setting_precedes_missing_or_blank_path_but_plain_missing_keeps_its_words() {
    for (value, extra) in [
        (serde_json::json!({"paht":"/x"}), "paht"),
        (serde_json::json!({"path":"  ","key":"X"}), "key"),
    ] {
        let error = resolve(value.as_object().unwrap()).err().expect("refused");
        assert_eq!(error_kind(error.kind), ERROR_KIND_INVALID);
        assert_eq!(error.message, format!("secret module 'file' does not take settings.{extra}; a reference names only settings.path (fail-closed)"));
    }
    let error = resolve(&serde_json::Map::new())
        .err()
        .expect("plain missing path refuses");
    assert_eq!(error.message, "secret module 'file' requires settings.path naming the file (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)");
}

/// RED (codeaudit secret-file LOW): a fifo (or device node) the process may not open is refused as
/// not a regular file (INVALID), as an openable one is, not DENIED "Permission denied"; the path's
/// type is judged before the open, so the open (and any device driver's open) never happens.
/// RED before the fix: it answered DENIED. As root the open succeeds and the answer is the same.
#[cfg(unix)]
#[test]
fn an_unopenable_fifo_is_refused_as_not_a_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let fifo = temp_path("fifo-denied");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo made the fifo");
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o000)).unwrap();
    let e = resolve(&path(&fifo));
    let _ = std::fs::remove_file(&fifo);
    let e = e.err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Invalid, "{}", e.message);
    assert_eq!(
        e.message,
        format!(
            "secret file:{} cannot resolve: the path is not a regular file (it is a device node or \
             fifo); a `file:` secret must name a regular file holding the credential bytes \
             (fail-closed)",
            fifo.display()
        )
    );
}

/// RED (codeaudit secret-file LOW): a setting key carrying newlines is named escaped, so `check`'s
/// FAILED reason keeps the validate refusal rule (no empty line) and the host shows it rather
/// than "refused the reference without saying why". RED before the fix: the key's blank line
/// broke the rule.
#[test]
fn a_setting_key_with_newlines_is_named_escaped_in_a_well_formed_refusal() {
    let mut s = serde_json::Map::new();
    s.insert("a\n\nb".into(), 1.into());
    let e = reference_path(&s).expect_err("refused");
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
    assert_eq!(
        e.message,
        "secret module 'file' does not take settings.a\\n\\nb; a reference names only \
         settings.path (fail-closed)"
    );
    assert!(
        busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(e.message.as_bytes())
            .is_ok(),
        "{}",
        e.message
    );
}

/// A first buffer no allocation can hold is refused UNAVAILABLE naming the path (the fallible
/// reservation's error), never an allocation abort.
#[cfg(target_pointer_width = "64")]
#[test]
fn a_first_buffer_no_allocation_can_hold_is_refused_not_an_abort() {
    let e = read_bounded(&mut std::io::empty(), u64::MAX, "/p/huge", |_| ())
        .err()
        .expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Unavailable, "{}", e.message);
    assert!(
        e.message
            .starts_with("secret file:/p/huge cannot resolve: "),
        "{}",
        e.message
    );
}

/// RED (codeaudit secret-file LOW): a path carrying control characters (a YAML block scalar's
/// kept newline, a pasted CR or ESC) is named ESCAPED in every refusal, so the refusal stays one
/// well-formed line and shows why the path did not match, as an unknown setting key already is.
#[test]
fn a_path_with_control_characters_is_named_escaped_in_a_well_formed_refusal() {
    let missing = temp_path("ctl-missing");
    let raw = format!("{}\n\u{1b}[2J\r", missing.display());
    let mut settings = serde_json::Map::new();
    settings.insert("path".into(), raw.clone().into());
    let e = resolve(&settings).err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::NotFound, "{}", e.message);
    assert!(!e.message.chars().any(char::is_control), "{:?}", e.message);
    assert!(
        e.message.starts_with(&format!(
            "secret file:{}\\n\\u{{1b}}[2J\\r cannot resolve: ",
            missing.display()
        )),
        "{:?}",
        e.message
    );

    // A file name holding a newline exists only where the filesystem allows one (not Windows).
    #[cfg(unix)]
    {
        let empty = temp_path("ctl-empty\n");
        std::fs::write(&empty, b"").unwrap();
        let e = resolve(&path(&empty)).err().expect("refused");
        let _ = std::fs::remove_file(&empty);
        assert_eq!(e.kind, SecretErrorKind::Invalid, "{}", e.message);
        assert!(e.message.contains("EMPTY"), "{:?}", e.message);
        assert!(!e.message.chars().any(char::is_control), "{:?}", e.message);
    }

    let over = over_bound("/run/secrets/x\n");
    assert!(
        !over.message.chars().any(char::is_control),
        "{:?}",
        over.message
    );
}

/// RED (codeaudit secret-file NIT): a unix socket is refused (INVALID, never opened) as what it
/// is, not misnamed "a device node or fifo".
#[cfg(unix)]
#[test]
fn a_socket_is_refused_as_a_socket() {
    let sock = temp_path("sock");
    let _ = std::fs::remove_file(&sock);
    let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind the socket");
    let e = resolve(&path(&sock));
    drop(listener);
    let _ = std::fs::remove_file(&sock);
    let e = e.err().expect("refused");
    assert_eq!(e.kind, SecretErrorKind::Invalid, "{}", e.message);
    assert!(
        e.message.contains("is not a regular file (it is a socket)"),
        "{}",
        e.message
    );
}

/// A non-blank path is opened exactly as written: a name with leading and trailing spaces names
/// that file, never its trimmed spelling (the blank check trims; the open must not).
#[test]
fn a_non_blank_path_is_opened_untrimmed() {
    let dir = temp_path("untrimmed");
    std::fs::create_dir_all(&dir).unwrap();
    let spaced = dir.join(" key ");
    std::fs::write(&spaced, b"spaced").unwrap();
    std::fs::write(dir.join("key"), b"trimmed").unwrap();
    let got = resolve(&path(&spaced));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(got.expect("resolves") == Held::new(b"spaced".to_vec()));
}
