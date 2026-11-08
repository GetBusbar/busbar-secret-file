// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `file` SECRET SOURCE for busbar's `kind: secret` plugin family, on the secret kind's memory
//! ABI (`busbar_contract::abi::secret`). This crate is the LOGIC and its door ([`door::door`]); the
//! dropped-in `cdylib` is the sibling `busbar-secret-file-plugin` crate, which exports the same door
//! as `busbar_plugin_door`.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
use busbar_contract::abi::sdk::cred::Held;
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};

mod door;

/// The word config names this source by: its module alias and its reference sugar
/// (`{ file: X }`), spelled here, never by the contract.
pub(crate) const WORD: &str = "file";

/// The settings key the sugar's value lands under (`{ file: X }` → `settings.path`).
pub(crate) const KEY: &str = "path";

/// Where a reference names its value, as a refusal of instance settings says it (the SDK's
/// `takes_no_settings`, at `validate`, `open` and `refresh` alike).
pub(crate) const NAMES: &str = "file in its own settings.path";

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-secret-file";

/// The plugin's `declares` section (its `declares.json`), as a linked build reads it beside a
/// dropped-in copy's signed one: this source reads the disk (`"disk": true`), so the host resolves
/// it only at config time, on its bounded disk lane.
pub const DECLARES: &str = include_str!("../declares.json");

/// The most bytes one secret may answer: the secret kind's answer bound (busbar-contract
/// `abi/mechanism/check.rs`), which the read refuses itself so the refusal names the path.
const MAX: usize = HARD_MAX_BYTES as usize;

/// `path` as a refusal names it: control characters (a kept newline, a CR, an ESC) escaped, so
/// the refusal stays one well-formed line; any other path reads exactly as written.
fn shown(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The refusal a file above [`MAX`] reads as: the path and the bound, never the content.
fn over_bound(path: &str) -> SecretModuleError {
    let path = shown(path);
    SecretModuleError::invalid(format!(
        "secret file:{path} cannot resolve: the file is larger than {HARD_MAX_BYTES} bytes, the \
         most a secret may hold (fail-closed)"
    ))
}

/// What a path that is not a regular file is refused as (an `Other` error, so [`io_refusal`] makes
/// it `Invalid` and names the path once, before `cannot resolve: `).
fn not_regular(md: &std::fs::Metadata) -> std::io::Error {
    #[cfg(unix)]
    let socket = std::os::unix::fs::FileTypeExt::is_socket(&md.file_type());
    #[cfg(not(unix))]
    let socket = false;
    let kind = if md.is_dir() {
        "a directory"
    } else if socket {
        "a socket"
    } else {
        "a device node or fifo"
    };
    std::io::Error::other(format!(
        "the path is not a regular file (it is {kind}); a `file:` secret must name a regular file \
         holding the credential bytes (fail-closed)"
    ))
}

/// Read `path` whole (like `std::fs::read`), once the OPENED handle is a regular
/// file (its `fstat`, not whatever the path named before the open). A path that already names
/// something else (a directory, a device node, a fifo) is refused before it is opened, so an
/// unopenable one reads as what it is, not DENIED, and no device driver sees an open. `seen`
/// observes each buffer holding file bytes ([`read_bounded`]).
fn read_file(path: &str, seen: impl FnMut(&[u8])) -> SecretResult<Held<Vec<u8>>> {
    let io = |e: std::io::Error| io_refusal(path, &e);
    if let Some(md) = std::fs::metadata(path).ok().filter(|md| !md.is_file()) {
        return Err(io(not_regular(&md)));
    }
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
    read_bounded(&mut file, md.len(), path, seen)
}

/// The bounded, wiped read loop of [`read_file`], over any reader: `hint` is the length the opened
/// handle stated (it sizes the first buffer; a reader may yield more or fewer bytes than it).
/// `seen` is shown every buffer that holds file bytes, as it holds them (the wipe tests' probe;
/// [`resolve`] passes a no-op).
fn read_bounded(
    r: &mut impl std::io::Read,
    hint: u64,
    path: &str,
    mut seen: impl FnMut(&[u8]),
) -> SecretResult<Held<Vec<u8>>> {
    use zeroize::Zeroizing;

    let io = |e: std::io::Error| io_refusal(path, &e);

    let len = usize::try_from(hint).unwrap_or(MAX);
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(len.saturating_add(1))
        .map_err(|e| io(e.into()))?;
    let mut chunk = Zeroizing::new(vec![0_u8; 8192]);
    loop {
        let n = match r.read(&mut chunk[..]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            r => r.map_err(io)?,
        };
        if n == 0 {
            break;
        }
        seen(&chunk[..]);
        if buf.len() + n > MAX {
            return Err(over_bound(path));
        }
        if buf.len() + n > buf.capacity() {
            let mut bigger = Zeroizing::new(Vec::new());
            let want = (buf.len() + n).saturating_mul(2).min(MAX);
            bigger.try_reserve_exact(want).map_err(|e| io(e.into()))?;
            bigger.extend_from_slice(&buf);
            buf = bigger;
        }
        buf.extend_from_slice(&chunk[..n]);
        seen(&buf[..]);
    }
    Ok(Held::new(std::mem::take(&mut *buf)))
}

/// The refusal an I/O error reads as: its code, and a text naming the path and the cause.
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
    let path = shown(path);
    SecretModuleError::new(kind, format!("secret file:{path} cannot resolve: {e}"))
}

/// Resolve `settings` (`{ path: PATH }`) to the file's bytes, untouched, in a zeroizing [`Held`]
/// (no getter: it reaches the host only through the SDK's `resolve` answer).
///
/// # Errors
/// Fail-closed: a missing, unreadable, empty, non-regular or over-bound file is refused, and so
/// is a missing or blank `path` or a reference naming any setting but `path`. The text names the
/// path, never the content.
pub(crate) fn resolve(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<Held<Vec<u8>>> {
    let path = reference_path(settings)?;
    resolve_path(path, |_| ())
}

pub(crate) fn reference_path(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<&str> {
    if let Some(other) = settings.keys().find(|k| k.as_str() != KEY) {
        let other = other.escape_debug();
        return Err(SecretModuleError::invalid(format!(
            "secret module 'file' does not take settings.{other}; a reference names only \
             settings.path (fail-closed)"
        )));
    }
    let path = match settings.get(KEY).and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'file' requires settings.path naming the file \
                 (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)",
            ))
        }
    };
    Ok(path)
}

fn resolve_path(path: &str, seen: impl FnMut(&[u8])) -> SecretResult<Held<Vec<u8>>> {
    match read_file(path, seen) {
        Ok(bytes) if bytes.is_empty() => Err(SecretModuleError::invalid(format!(
            "secret file:{} resolved to an EMPTY file; a secret must be non-empty \
             (fail-closed)",
            shown(path)
        ))),

        r => r,
    }
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/wiping_tests.rs"]
mod wiping_tests;

/// The plugin ABI entry and generated registration constant.
pub use door::{door, MACRO_DOOR};
