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
//! Every refusal text is 1.5.5's, byte for byte; none carries the file's content.

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

/// The largest a `file:`-sourced secret is allowed to be. A secret is a credential (an API key, a
/// bearer token, a TLS private key or a short PEM chain, a service-account JSON blob) — never a
/// multi-megabyte payload — so 1 MiB is generous headroom above any realistic secret while still
/// bounding memory: `settings.path` can name any path the process can read (a device node such as
/// `/dev/zero`, a named pipe, an operator-controlled mount), and an unbounded read would buffer the
/// whole thing before the emptiness checks ever run, turning a misconfigured or hostile path into an
/// OOM.
pub const MAX_SECRET_FILE_BYTES: u64 = 1024 * 1024;

/// Read `path` with [`MAX_SECRET_FILE_BYTES`] enforced BEFORE the read buffers the content, not
/// after: `Read::take` caps the reader itself, so a file (or fifo, or device node) larger than the
/// limit never gets fully materialized in memory. A file over the cap is a hard error (fail-closed),
/// never a silent truncation — a truncated credential is worse than a rejected one.
fn read_bounded(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    // Read one byte PAST the cap: a file of exactly the limit is accepted, and a file one byte
    // over it is provably over, without ever buffering more than `MAX_SECRET_FILE_BYTES + 1` bytes.
    let mut limited = (&mut file).take(MAX_SECRET_FILE_BYTES + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file exceeds the {MAX_SECRET_FILE_BYTES}-byte secret size limit"
        )));
    }
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
/// Fail-closed: a missing, unreadable, non-regular, empty, whitespace-only or over-size file is
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
    // A path-shaped source must name a REGULAR FILE. A directory `open()`s fine on Unix and fails
    // only at read time with a bare errno ("Is a directory"), which does not tell an operator they
    // pointed the credential at a folder; a fifo opens and then BLOCKS until a writer appears,
    // hanging boot with no diagnostic at all. `fs::metadata` FOLLOWS symlinks, which is required:
    // Kubernetes projects every secret as a symlink into a `..data/` directory.
    //
    // A metadata error is deliberately NOT handled here — a missing or unreadable path falls
    // through to the read below so it keeps its "cannot resolve: <cause>" message.
    if let Ok(md) = std::fs::metadata(path) {
        if !md.is_file() {
            let kind = if md.is_dir() {
                "a directory"
            } else {
                "a device node, socket, or fifo"
            };
            return Err(SecretModuleError::invalid(format!(
                "secret file:{path} cannot resolve: '{path}' is not a regular file (it is \
                 {kind}); a `file:` secret must name a regular file holding the credential \
                 bytes (fail-closed)"
            )));
        }
    }
    match read_bounded(path) {
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
