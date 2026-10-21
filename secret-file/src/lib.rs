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
//! It is an ordinary plugin (THE DESIGN §2): linked in the default build or dropped in, called
//! through the secret kind table by the one dispatcher, and loaded only when a reference names it.
//! It reads the local disk, so its declares document ([`DECLARES`]) states the disk need: the host
//! runs its `resolve` on the bounded disk lane, at config time only (THE DESIGN §11.11 R4).
//!
//! It reads what 1.5.5 read (`std::fs::read`): whatever the path opens to, a directory, a device
//! or a fifo included, with 1.5.5's missing-path, EMPTY-file and `cannot resolve: <cause>` refusals
//! byte for byte; a whitespace-only file resolves to its bytes, as 1.5.5 resolved it. The one bound
//! is the secret kind's own: an answer above `HARD_MAX_BYTES` is one the host cannot take, so it is
//! refused naming the path. No refusal carries the file's content.

#![forbid(unsafe_code)]

use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
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

/// THE PLUGIN'S `declares` SECTION (its `declares.json`), as a linked build reads it beside a
/// dropped-in copy's signed one: this source reads the disk (`"disk": true`), so the host resolves
/// it only at config time, on its bounded disk lane, never from a request path (busbar
/// `BUSBAR-1.6.0.md` l.1464-1469, R4, OWNER 2026-10-13).
pub const DECLARES: &str = include_str!("../declares.json");

/// The most bytes one secret may answer: the secret kind's answer bound (busbar-contract
/// `abi/mechanism/check.rs`). The host's answer check turns a READY answer above it into a FAULT
/// naming neither the path nor the cause, so the read refuses it first.
const MAX: usize = HARD_MAX_BYTES as usize;

/// The refusal a source above [`MAX`] reads as: the path and the bound, never the content.
fn over_bound(path: &str) -> SecretModuleError {
    SecretModuleError::invalid(format!(
        "secret file:{path} cannot resolve: the file is larger than {HARD_MAX_BYTES} bytes, the \
         most a secret may hold (fail-closed)"
    ))
}

/// Read `path` whole, as 1.5.5 read it (`std::fs::read`): a BLOCKING open that follows symlinks
/// (Kubernetes projects every secret as a symlink into a `..data/` directory), then the handle
/// read to its end. Whatever the path opens to is read as 1.5.5 read it: a fifo or a piped
/// `/dev/stdin` once its writer supplies it, `/dev/null` as an empty file, and a directory refused
/// by the read's own error. On unix the open is NO-CTTY, so a terminal device never becomes the
/// process's controlling terminal; the bytes read are the same.
///
/// BOUNDED by [`MAX`], and only above it does anything differ from 1.5.5: a regular file whose
/// length is above it is refused before a byte is read, and any other source (a device, a fifo, a
/// file that grew) once it has yielded one byte past it. Nothing above it is ever leased.
///
/// THE BYTES ARE WIPED on every path but the one that hands them back (THE DESIGN §6: auth
/// material is zeroised): they are read into a wiped buffer sized from the handle's length, a
/// source that grows past it moves into a larger wiped buffer (the old one wiped as it goes), and
/// an I/O error or the bound mid-read drops what was read wiped.
fn read_file(path: &str) -> SecretResult<Vec<u8>> {
    use std::io::Read;
    use zeroize::Zeroizing;

    let io = |e: std::io::Error| io_refusal(path, &e);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOCTTY);
    }
    let mut file = options.open(path).map_err(io)?;
    // The length is a hint, as `std::fs::read` took it: a handle with none reads as one of length 0.
    let len = match file.metadata() {
        Ok(md) if md.is_file() && md.len() > HARD_MAX_BYTES => return Err(over_bound(path)),
        Ok(md) if md.is_file() => usize::try_from(md.len()).unwrap_or(MAX),
        _ => 0,
    };
    // FALLIBLE, as `std::fs::read` reserved (`try_reserve_exact`): memory the read cannot get is
    // refused with the allocator's error, never an abort of the process.
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
    Ok(std::mem::take(&mut *buf))
}

/// The refusal an I/O error reads as: its code, and 1.5.5's text naming the path and the cause.
/// The code is the contract's taxonomy (App. A B.2; `abi::secret::ERROR_KIND_*`): a path the
/// operator got wrong (missing, not permitted, through a regular file, a loop, a directory, an
/// over-long or NUL-bearing name, a socket) is a CONFIG error; a filesystem that could not be
/// reached (a failing disk's `EIO`, memory the read could not get, a stale or busy handle) is
/// `Unavailable`, and so is any cause not named here.
fn io_refusal(path: &str, e: &std::io::Error) -> SecretModuleError {
    use std::io::ErrorKind as K;
    let kind = match e.kind() {
        K::NotFound => SecretErrorKind::NotFound,
        K::PermissionDenied => SecretErrorKind::Denied,
        K::NotADirectory
        | K::IsADirectory
        | K::InvalidFilename
        | K::InvalidInput
        | K::Unsupported
        | K::Other => SecretErrorKind::Invalid,
        _ if operator_errno(e) => SecretErrorKind::Invalid,
        _ => SecretErrorKind::Unavailable,
    };
    SecretModuleError::new(kind, format!("secret file:{path} cannot resolve: {e}"))
}

/// The path errors with no stable `ErrorKind` on the pinned toolchain, judged by their errno: a
/// symlink loop (`ELOOP`) and a socket or absent device (`ENXIO`).
fn operator_errno(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENXIO))
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// Resolve `settings` (`{ path: PATH }`) to the file's bytes, untouched.
///
/// # Errors
/// Fail-closed, as 1.5.5: a missing, unreadable or empty file is refused, and so is a missing or
/// blank `path`; a source above the answer bound is refused naming it. The text names the path,
/// never the content.
pub fn resolve(settings: &serde_json::Map<String, serde_json::Value>) -> SecretResult<Vec<u8>> {
    let path = match settings.get(KEY).and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'file' requires settings.path naming the file \
                 (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)",
            ))
        }
    };
    match read_file(path) {
        Ok(bytes) if bytes.is_empty() => Err(SecretModuleError::invalid(format!(
            "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
             (fail-closed)"
        ))),
        // Any other content resolves untouched, a whitespace-only file included, as 1.5.5 resolved
        // it (`resolve_builtin` tested a file only for emptiness): a PEM chain's trailing newline
        // is part of the secret, and a binary secret need not be UTF-8.
        r => r,
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
