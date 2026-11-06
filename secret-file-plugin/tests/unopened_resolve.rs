// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin's OWN refusal of a resolve with no instance. The host never crosses an unopened
//! resolve (conformance's `resolve_unopened` is the host refusing), so the door's guard is driven
//! here directly through the linked door's raw `resolve` op: with no instance it answers REFUSED
//! and writes nothing into the host's buffer, while the same call on an instance the door opened
//! answers READY with the file's bytes.

use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, OpenIn, OpenOut};
use busbar_contract::abi::secret::{self, Ops, ResolveIn, ResolveOut, ERROR_KIND_UNSET};
use busbar_plugin_loader::dispatch::{in_head, out_head, NO_BLOB};

const VALUE: &[u8] = b"s3cr3t-unopened-resolve";

/// The linked door's secret ops table.
fn ops() -> &'static Ops {
    // SAFETY: `door()` is the SDK's static door; its `ops` is the static secret `Ops` table.
    unsafe {
        &*Door::read_parts(busbar_secret_file::door::door())
            .ops
            .cast::<Ops>()
    }
}

/// An `in` head for slot `op` of an `in` frame of type `T`.
fn head<T>(op: u32) -> InHead {
    InHead {
        size: u32::try_from(size_of::<T>()).unwrap(),
        op,
        ..in_head()
    }
}

/// An `out` head for an `out` frame of type `T`.
fn out_of<T>() -> OutHead {
    OutHead {
        size: u32::try_from(size_of::<T>()).unwrap(),
        ..out_head()
    }
}

/// Call `op` on `instance` over its `input` and `out` frames.
fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    let op = op.expect("the door wires this op");
    // SAFETY: `input`/`out` are the op's own live `in`/`out` frames; `instance` is NULL or one the
    // door's own `open` minted and has not closed.
    let RawOutcome(raw) = unsafe {
        op(
            instance,
            std::ptr::from_ref(input).cast(),
            std::ptr::from_mut(out).cast(),
        )
    };
    match raw {
        r if r == RawOutcome::of(Outcome::Ready).0 => Outcome::Ready,
        r if r == RawOutcome::of(Outcome::Refused).0 => Outcome::Refused,
        r if r == RawOutcome::of(Outcome::Failed).0 => Outcome::Failed,
        r if r == RawOutcome::of(Outcome::Pending).0 => Outcome::Pending,
        _ => Outcome::Fault,
    }
}

/// One resolve of `path` on `instance` into a zeroed host buffer: the answer, the out frame and
/// the buffer as the call left it.
fn resolve(instance: *mut c_void, path: &str) -> (Outcome, ResolveOut, Vec<u8>) {
    let settings = serde_json::json!({ "path": path }).to_string().into_bytes();
    let mut buf = vec![0_u8; secret::FIRST_SECRET_CAP];
    let input = ResolveIn {
        head: head::<ResolveIn>(secret::slot::RESOLVE),
        // SAFETY: `settings` is valid JSON and outlives the call.
        settings: unsafe { Blob::from_raw_parts(settings.as_ptr(), settings.len(), BLOB_JSON, 0) },
        secret_buf: buf.as_mut_ptr(),
        secret_cap: buf.len(),
    };
    let mut out = ResolveOut {
        head: out_of::<ResolveOut>(),
        secret: NO_BLOB,
        error_kind: ERROR_KIND_UNSET,
        _reserved: 0,
        needed: 0,
    };
    let answer = call(ops().resolve, instance, &input, &mut out);
    (answer, out, buf)
}

#[test]
fn a_resolve_with_no_instance_is_refused_by_the_plugin_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-secret-file-unopened-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("value");
    std::fs::write(&file, VALUE).unwrap();
    let path = file.to_str().unwrap();

    let (answer, out, buf) = resolve(std::ptr::null_mut(), path);
    assert_eq!(answer, Outcome::Refused, "no instance: the plugin refuses");
    assert!(
        out.secret.ptr.is_null() && out.secret.len == 0,
        "a refusal names no material"
    );
    assert_eq!(out.error_kind, ERROR_KIND_UNSET);
    assert!(
        buf.iter().all(|b| *b == 0),
        "a refusal wrote file bytes into the host buffer"
    );

    // The same resolve on an instance the door opened serves the file: the refusal above is the
    // missing instance, not the reference.
    let open_in = OpenIn {
        head: head::<OpenIn>(lc::OPEN),
        host: std::ptr::null(),
        settings: NO_BLOB,
        secrets: std::ptr::null(),
        secrets_len: 0,
        generation: 1,
        err_buf: std::ptr::null_mut(),
        err_cap: 0,
    };
    let mut open_out = OpenOut {
        head: out_of::<OpenOut>(),
        instance: std::ptr::null_mut(),
        err_len: 0,
    };
    assert_eq!(
        call(
            ops().head.open,
            std::ptr::null_mut(),
            &open_in,
            &mut open_out
        ),
        Outcome::Ready
    );
    let instance = open_out.instance;
    assert!(!instance.is_null(), "open minted an instance");

    let (answer, out, buf) = resolve(instance, path);
    assert_eq!(answer, Outcome::Ready);
    assert_eq!(
        out.secret.ptr,
        buf.as_ptr().cast_mut(),
        "the value is in the host's buffer"
    );
    assert_eq!(&buf[..out.secret.len], VALUE);

    let close_in = head::<InHead>(lc::CLOSE);
    let mut close_out = out_of::<OutHead>();
    assert_eq!(
        call::<InHead, OutHead>(ops().head.close, instance, &close_in, &mut close_out),
        Outcome::Ready
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
