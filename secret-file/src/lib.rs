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
//! The missing-path, EMPTY-file and `cannot resolve: <cause>` refusals are 1.5.5's, byte for byte;
//! the BLANK-file and not-a-regular-file refusals are new in 1.6.0 (registered in busbar's
//! CHANGELOG). No refusal carries the file's content.

#![forbid(unsafe_code)]

use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};
use busbar_contract::secret_ref::SECRET_FILE_SETTING_PATH;

pub mod door;

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-secret-file";

/// The manifest `declares` section (`--declares-file` for the signed tarball; the linked row's
/// `linked-declares` in busbar): the disk need.
pub const DECLARES: &str = include_str!("../declares.json");

/// What a path that is not a regular file is refused as (an `Other` error, so [`io_refusal`] makes
/// it `Invalid`, and its text follows `cannot resolve: `). A directory `open()`s fine on Unix and
/// fails only at read time with a bare errno ("Is a directory"), which does not tell an operator
/// they pointed the credential at a folder; a fifo opens and then BLOCKS until a writer appears; a
/// device node such as `/dev/zero` never ends.
fn not_regular(path: &str, md: &std::fs::Metadata) -> std::io::Error {
    let kind = if md.is_dir() {
        "a directory"
    } else {
        "a device node, socket, or fifo"
    };
    std::io::Error::other(format!(
        "'{path}' is not a regular file (it is {kind}); a `file:` secret must name a regular file \
         holding the credential bytes (fail-closed)"
    ))
}

/// Read `path` whole, as 1.5.5 read it (`std::fs::read`), once the OPENED handle is a regular
/// file: the type is judged on what was opened, not on whatever the path named before the open.
fn read_file(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(not_regular(path, &md));
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// The refusal an I/O error reads as: its code, and 1.5.5's text naming the path and the cause.
fn io_refusal(path: &str, e: &std::io::Error) -> SecretModuleError {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => SecretErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => SecretErrorKind::Denied,
        std::io::ErrorKind::Other => SecretErrorKind::Invalid,
        _ => SecretErrorKind::Unavailable,
    };
    SecretModuleError::new(kind, format!("secret file:{path} cannot resolve: {e}"))
}

/// Resolve `settings` (`{ path: PATH }`) to the file's bytes, untouched.
///
/// # Errors
/// Fail-closed: a missing, unreadable, non-regular, empty or whitespace-only file is
/// refused, and so is a missing or blank `path`. The text names the path, never the content.
pub fn resolve(settings: &serde_json::Map<String, serde_json::Value>) -> SecretResult<Vec<u8>> {
    let path = match settings
        .get(SECRET_FILE_SETTING_PATH)
        .and_then(|v| v.as_str())
    {
        Some(p) if !p.trim().is_empty() => p,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'file' requires settings.path naming the file \
                 (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)",
            ))
        }
    };
    // A path-shaped source must name a REGULAR FILE ([`not_regular`]), judged here on the path
    // before the open so a fifo is never opened (an open of one blocks until a writer appears), and
    // again on the opened handle ([`read_file`]). `fs::metadata` FOLLOWS symlinks, which is
    // required: Kubernetes projects every secret as a symlink into a `..data/` directory.
    //
    // A metadata error is deliberately NOT handled here — a missing or unreadable path falls
    // through to the read below so it keeps its "cannot resolve: <cause>" message.
    if let Ok(md) = std::fs::metadata(path) {
        if !md.is_file() {
            return Err(io_refusal(path, &not_regular(path, &md)));
        }
    }
    match read_file(path) {
        Ok(bytes) if bytes.is_empty() => Err(SecretModuleError::invalid(format!(
            "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
             (fail-closed)"
        ))),
        // The `env:` blank rule, in BYTE form: "every byte is ASCII whitespace", NOT "the bytes
        // decode to a blank string" — a binary secret (a DER key, a raw 32-byte token) is often not
        // UTF-8 and must keep resolving. Bytes that pass are returned untouched: a PEM chain's
        // trailing newline is part of the secret.
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => {
            Err(SecretModuleError::invalid(format!(
                "secret file:{path} resolved to a BLANK file (whitespace only); a secret must \
                 carry actual content, and the file DOES exist — fix its contents, not its \
                 presence (fail-closed)"
            )))
        }
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(io_refusal(path, &e)),
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
