// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `file` SECRET SOURCE for busbar's `kind: secret` plugin family, on the secret kind's memory
//! ABI (`busbar_contract::abi::secret`). This crate is the LOGIC and its door ([`door::door`]); the
//! dropped-in `cdylib` is the sibling `busbar-secret-file-plugin` crate, which exports the same door
//! as `busbar_plugin_door`.
//!
//! `resolve` reads the file its settings' `path` names. `{ file: PATH }` is the reference sugar for
//! `{ module: file, settings: { path: PATH } }`.
//!
//! It is an ordinary plugin: linked in the default build or dropped in, called through the secret
//! kind table by the one dispatcher, and loaded only when a reference names it. It reads the local
//! disk, so its declares document ([`DECLARES`]) states the disk need: the host runs its `resolve`
//! on the bounded disk lane, at config time only.
//!
//! Refused: a missing path, an EMPTY file (`cannot resolve: <cause>`), a file that is not regular, a
//! reference naming a setting other than `path`, and instance settings, which this source takes
//! none of ([`instance_settings`]). A whitespace-only file resolves to its bytes. The one bound is the secret kind's own: a file above
//! `HARD_MAX_BYTES` is an answer the host cannot take, so it is refused naming the path. No refusal
//! carries the file's content.

#![forbid(unsafe_code)]

use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
use busbar_contract::abi::sdk::cred::Held;
use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};

pub mod door;

/// The word config names this source by: its module alias and its reference sugar
/// (`{ file: X }`), spelled here, never by the contract (busbar step 2c).
pub const WORD: &str = "file";

/// The settings key the sugar's value lands under (`{ file: X }` → `settings.path`).
pub const KEY: &str = "path";

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-secret-file";

/// The plugin's `declares` section (its `declares.json`), as a linked build reads it beside a
/// dropped-in copy's signed one: this source reads the disk (`"disk": true`), so the host resolves
/// it only at config time, on its bounded disk lane, never from a request path.
pub const DECLARES: &str = include_str!("../declares.json");

/// The most bytes one secret may answer: the secret kind's answer bound (busbar-contract
/// `abi/mechanism/check.rs`). The host's answer check turns a READY answer above it into a FAULT
/// naming neither the path nor the cause, so the read refuses it first.
const MAX: usize = HARD_MAX_BYTES as usize;

/// The refusal a file above [`MAX`] reads as: the path and the bound, never the content.
fn over_bound(path: &str) -> SecretModuleError {
    SecretModuleError::invalid(format!(
        "secret file:{path} cannot resolve: the file is larger than {HARD_MAX_BYTES} bytes, the \
         most a secret may hold (fail-closed)"
    ))
}

/// What a path that is not a regular file is refused as (an `Other` error, so [`io_refusal`] makes
/// it `Invalid`, and its text follows `cannot resolve: `). A directory `open()`s fine on Unix and
/// fails only at read time with a bare errno ("Is a directory"), which does not tell an operator
/// they pointed the credential at a folder; a fifo would BLOCK a blocking open until a writer
/// appears; a device node such as `/dev/zero` never ends. (A unix socket does not open at all: it
/// is refused by the open's own error.)
/// The path is not repeated here: [`io_refusal`] names it once, before `cannot resolve: `.
fn not_regular(md: &std::fs::Metadata) -> std::io::Error {
    let kind = if md.is_dir() {
        "a directory"
    } else {
        "a device node or fifo"
    };
    std::io::Error::other(format!(
        "the path is not a regular file (it is {kind}); a `file:` secret must name a regular file \
         holding the credential bytes (fail-closed)"
    ))
}

/// Read `path` whole (like `std::fs::read`), once the OPENED handle is a regular
/// file: the type is judged on what was opened (its `fstat`), not on whatever the path named
/// before the open. On unix the open is NON-BLOCKING, so a fifo (which a blocking open waits on
/// until a writer appears) is opened at once and refused here, and NO-CTTY, so a terminal device
/// never becomes the process's controlling terminal before it is refused; a regular file reads
/// the same either way.
///
/// BOUNDED by [`MAX`]: a file whose length is above it is refused before a byte is read, and one
/// that grows past it mid-read once it has yielded one byte past it. Nothing above it is answered.
///
/// The bytes are WIPED on every path: they are read into a wiped buffer sized from the handle's
/// length, a file that grows mid-read moves into a larger wiped buffer (the old one wiped as it
/// goes), an I/O error or the bound mid-read drops what was read wiped, and what is read is MOVED
/// (never copied) into the zeroizing [`Held`] it answers.
fn read_file(path: &str) -> SecretResult<Held<Vec<u8>>> {
    use std::io::Read;
    use zeroize::Zeroizing;

    let io = |e: std::io::Error| io_refusal(path, &e);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let mut file = options.open(path).map_err(io)?;
    let md = file.metadata().map_err(io)?;
    if !md.is_file() {
        return Err(io(not_regular(&md)));
    }
    if md.len() > HARD_MAX_BYTES {
        return Err(over_bound(path));
    }
    // FALLIBLE (`try_reserve_exact`, as `std::fs::read` does): memory the read cannot
    // get is refused with the allocator's error, never an abort of the process.
    let len = usize::try_from(md.len()).unwrap_or(MAX);
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(len.saturating_add(1))
        .map_err(|e| io(e.into()))?;
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    loop {
        // An interrupted read is retried, as `read_to_end` retried it.
        let n = match file.read(&mut chunk[..]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            r => r.map_err(io)?,
        };
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX {
            return Err(over_bound(path));
        }
        if buf.len() + n > buf.capacity() {
            // Grown past its length: a larger wiped buffer takes the bytes, never past the bound,
            // and the old one is wiped as it drops.
            let mut bigger = Zeroizing::new(Vec::new());
            let want = (buf.len() + n).saturating_mul(2).min(MAX);
            bigger.try_reserve_exact(want).map_err(|e| io(e.into()))?;
            bigger.extend_from_slice(&buf);
            buf = bigger;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(Held::new(std::mem::take(&mut *buf)))
}

/// The refusal an I/O error reads as: its code, and a text naming the path and the cause.
/// The code is the contract's taxonomy (App. A B.2): a path the operator got wrong (missing, not
/// permitted, through a regular file, a loop, a directory, an over-long or NUL-bearing name) is a
/// CONFIG error; a transient I/O failure (including a network-filesystem outage and file
/// descriptor exhaustion), a failing disk (`EIO`) and memory the read could not get are an outage
/// (`Unavailable`), and anything else defaults to the config kind, never to an outage nobody can
/// wait out.
fn io_refusal(path: &str, e: &std::io::Error) -> SecretModuleError {
    use std::io::ErrorKind as K;
    #[cfg(unix)]
    let outage_errno = matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::EIO)
    );
    #[cfg(not(unix))]
    let outage_errno = false;
    let kind = match e.kind() {
        _ if outage_errno => SecretErrorKind::Unavailable,
        K::NotFound => SecretErrorKind::NotFound,
        K::PermissionDenied => SecretErrorKind::Denied,
        K::Interrupted
        | K::TimedOut
        | K::WouldBlock
        | K::ResourceBusy
        | K::StaleNetworkFileHandle
        | K::NetworkDown
        | K::NetworkUnreachable
        | K::HostUnreachable
        | K::ConnectionReset
        | K::ConnectionAborted
        | K::NotConnected
        | K::OutOfMemory => SecretErrorKind::Unavailable,
        _ => SecretErrorKind::Invalid,
    };
    SecretModuleError::new(kind, format!("secret file:{path} cannot resolve: {e}"))
}

/// Resolve `settings` (`{ path: PATH }`) to the file's bytes, untouched, in a zeroizing [`Held`]
/// (no getter: it reaches the host only through the SDK's `resolve` answer).
///
/// # Errors
/// Fail-closed: a missing, unreadable or empty file is refused, and so is a missing or
/// blank `path`; a non-regular file is refused by name, and so is a reference naming any setting
/// but `path`. The text names the path, never the content.
pub fn resolve(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<Held<Vec<u8>>> {
    let path = match settings.get(KEY).and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'file' requires settings.path naming the file \
                 (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)",
            ))
        }
    };
    if let Some(other) = settings.keys().find(|k| k.as_str() != KEY) {
        return Err(SecretModuleError::invalid(format!(
            "secret module 'file' does not take settings.{other}; a reference names only \
             settings.path (fail-closed)"
        )));
    }
    // A path-shaped source must name a REGULAR FILE ([`not_regular`]), judged on the OPENED handle
    // ([`read_file`], opened non-blocking so a fifo is never waited on): one open, one judgement,
    // with no path lookup before it a swapped path could slip past. The open FOLLOWS symlinks,
    // which is required: Kubernetes projects every secret as a symlink into a `..data/` directory.
    match read_file(path) {
        Ok(bytes) if bytes.is_empty() => Err(SecretModuleError::invalid(format!(
            "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
             (fail-closed)"
        ))),
        // Any other content resolves untouched, a whitespace-only file included: a PEM
        // chain's trailing newline is part of the secret, and a binary secret need not be UTF-8.
        r => r,
    }
}

/// The instance settings (`secrets.file.settings`) as this source takes them: none. Empty bytes or
/// an empty object open it; anything else is refused naming why, at `validate`, `open` and
/// `refresh` alike, rather than ignored.
///
/// # Errors
/// The settings are not a JSON object, or name a setting.
pub fn instance_settings(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(m)) => match m.keys().next() {
            None => Ok(()),
            Some(k) => Err(format!(
                "secret module 'file' takes no settings; remove settings.{k} (each reference \
                 names its file in its own settings.path)"
            )),
        },
        _ => Err("settings: must be a JSON object".to_string()),
    }
}

/// A resolve's settings bytes as the JSON object they must be (empty = none).
///
/// # Errors
/// The bytes are not a JSON object.
pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

/// The `abi::secret::ERROR_KIND_*` code of a [`SecretErrorKind`].
#[must_use]
pub const fn error_kind(kind: SecretErrorKind) -> u32 {
    match kind {
        SecretErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
        SecretErrorKind::Unavailable => ERROR_KIND_UNAVAILABLE,
        SecretErrorKind::Denied => ERROR_KIND_DENIED,
        SecretErrorKind::Invalid => ERROR_KIND_INVALID,
        SecretErrorKind::Internal => ERROR_KIND_INTERNAL,
    }
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
