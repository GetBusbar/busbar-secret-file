// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FILE PLUGIN, BOTH DOORS, ONE TABLE** — the `file` secret source's linked + dropped-in
//! conformance on the secret kind's memory ABI (THE DESIGN §2 "Each plugin tests itself", §11.4),
//! run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, through the
//! loader's `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the loader's
//! `load_dropped`, which resolves `busbar_plugin_door` and validates the door). Each is bound to a
//! real dispatcher and driven over the same script through the secret kind's table: `validate`,
//! `open`, `resolve` over a present, a missing, an empty and a malformed reference, `release` of the
//! granted lease and of one never granted, `refresh`, `tick`, `close`. The two transcripts must be
//! equal, and the resolved value is read out of the lease the READY answer names.
//!
//! The dropped-in door is admitted against the Statement rendering `busbar-plugin-pack` signs into
//! its manifest (`rendering_of_library`, read off the built cdylib); the linked row states its own
//! (`LinkedRow::of`). The two renderings must be equal byte for byte.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a manifest stating
//! another kind, or 1.5.5's secret ABI version, is refused before `dlopen` (ABI-b6: a 1.5.5 secret
//! plugin is refused naming the rebuild). A missing cdylib PANICS — this test IS the dropped-in
//! door's proof, and never skips.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, Bind, Called,
    DispatchConfig, Dispatcher, Frame, LinkedRow, LoadError, NoSink, Plugin, NO_BLOB,
};

/// The value the present file holds; the transcript carries it only as the resolved material.
const VALUE: &str = "s3cr3t-file-conformance";

/// The three fixture paths (present, empty, missing), under one per-process temp directory.
fn fixtures() -> (String, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-secret-file-conformance-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let (set, empty, unset) = (dir.join("set"), dir.join("empty"), dir.join("unset"));
    std::fs::write(&set, VALUE).expect("the present fixture");
    std::fs::write(&empty, b"").expect("the empty fixture");
    let s = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
    (s(set), s(empty), s(unset))
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_secret_file_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-secret-file-plugin cdylib ({file}) is not built"))
}

/// The Statement rendering the signed manifest states for the dropped-in image.
fn stated() -> Vec<u8> {
    rendering_of_library(&cdylib())
        .expect("the cdylib's Statement renders")
        .expect("the cdylib exports busbar_plugin_door")
}

/// [`stated`] with head words (0 mechanism version, 1 kind, 2 kind ABI, after the magic) replaced.
fn stating(words: &[(usize, u32)]) -> Vec<u8> {
    let mut r = stated();
    for &(word, value) in words {
        let at = RENDERING_MAGIC.len() + 4 * word;
        r[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    r
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("file"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn linked(d: &Dispatcher) -> Plugin<Secret> {
    let row = LinkedRow::of(busbar_secret_file::door::door).expect("the linked row states");
    load_linked::<Secret>(&row, bind(d)).expect("the linked door loads")
}

fn dropped(d: &Dispatcher) -> Plugin<Secret> {
    load_dropped::<Secret>(&cdylib(), &stated(), bind(d)).expect("the dropped-in door loads")
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn validate(p: &Plugin<Secret>, settings: &str) -> String {
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    spelled(&p.call(lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Secret>) -> String {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    spelled(&p.call(lc::OPEN, &mut f))
}

fn refresh(p: &Plugin<Secret>) -> String {
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    spelled(&p.call(lc::REFRESH, &mut f))
}

/// One resolve: its answer, its error kind, the material it leased (read out of the lease), and
/// the lease released.
fn resolve(p: &Plugin<Secret>, settings: &str) -> String {
    let mut f = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
        },
    );
    let c = p.call(secret::slot::RESOLVE, &mut f);
    let blob = f.out.secret;
    let material = if blob.ptr.is_null() || blob.len == 0 {
        String::new()
    } else {
        // SAFETY: a READY resolve's `secret` names plugin memory held under the answer's lease
        // until `release`, which runs below, after this copy.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) })
            .into_owned()
    };
    let released = if c.lease == 0 {
        String::new()
    } else {
        format!(" released={}", release(p, c.lease))
    };
    format!(
        "{} kind={} material={material:?}{released}",
        spelled(&c),
        f.out.error_kind
    )
}

fn release(p: &Plugin<Secret>, lease: u64) -> String {
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    spelled(&p.call(lc::RELEASE, &mut f))
}

fn tick(p: &Plugin<Secret>) -> String {
    let mut f = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 7,
        },
    );
    let c = p.call(lc::TICK, &mut f);
    format!("{} next={}", spelled(&c), f.out.next_tick_ns)
}

fn close(p: &Plugin<Secret>) -> String {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    spelled(&p.call(lc::CLOSE, &mut f))
}

/// What one door does, as one comparable transcript.
fn transcript(p: &Plugin<Secret>) -> serde_json::Value {
    let (set, empty, unset) = fixtures();
    let resolved: Vec<String> = [
        format!(r#"{{"path":"{set}"}}"#),
        format!(r#"{{"path":"{unset}"}}"#),
        format!(r#"{{"path":"{empty}"}}"#),
        r#"{"path":"  "}"#.to_string(),
        "[1]".to_string(),
    ]
    .iter()
    .map(|s| resolve(p, s))
    .collect();
    serde_json::json!({
        "name": p.name(),
        "kind": format!("{:?}", p.kind()),
        "max_inflight": p.max_inflight(),
        "validate": [validate(p, ""), validate(p, "{}"), validate(p, "[1]")],
        "resolve_unopened": resolve(p, &format!(r#"{{"path":"{set}"}}"#)),
        "open": open(p),
        "open_again": open(p),
        "resolve": resolved,
        "release_unknown": release(p, 42),
        "refresh": refresh(p),
        "tick": tick(p),
        "close": close(p),
    })
}

/// The plugin answers as ONE plugin through either door, with 1.5.5's refusal texts.
#[test]
fn the_linked_and_the_dropped_in_file_plugin_are_one_plugin() {
    let (set, empty, unset) = fixtures();
    assert_eq!(std::fs::read(&set).unwrap(), VALUE.as_bytes());
    assert_eq!(
        LinkedRow::of(busbar_secret_file::door::door)
            .expect("the linked row states")
            .statement,
        stated(),
        "the linked and the dropped-in door state different Statements"
    );
    let stated_read = busbar_contract::abi::mechanism::rendering::read(&stated())
        .unwrap_or_else(|e| panic!("the rendering reads back: byte {} is not {}", e.at, e.what));
    assert_eq!(
        stated_read.rewrites,
        vec![
            (
                busbar_contract::abi::mechanism::door::REWRITE_ALIAS,
                "file".to_string(),
                String::new()
            ),
            (
                busbar_contract::abi::mechanism::door::REWRITE_SUGAR,
                "file".to_string(),
                String::new()
            ),
        ],
        "the Statement names the source by its module alias and its reference sugar"
    );
    let d = dispatcher();
    let linked = transcript(&linked(&d));
    let dropped_in = transcript(&dropped(&d));
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    assert_eq!(linked["name"], busbar_secret_file::NAME);
    assert_eq!(linked["kind"], "Secret");
    assert_eq!(linked["max_inflight"], 16);
    assert_eq!(
        linked["validate"],
        serde_json::json!([
            "Ready lease=false ",
            "Ready lease=false ",
            "Failed lease=false settings: must be a JSON object",
        ])
    );
    assert!(
        linked["resolve_unopened"]
            .as_str()
            .unwrap()
            .starts_with("Refused lease=false "),
        "an unopened instance serves no resolve: {}",
        linked["resolve_unopened"]
    );
    assert_eq!(linked["open"], "Ready lease=false ");
    assert_eq!(
        linked["open_again"], "Refused lease=false ",
        "one open per instance"
    );
    eprintln!("the linked transcript: {linked:#}");
    let mut resolved = linked["resolve"].clone();
    let not_object = resolved[4].as_str().unwrap().to_string();
    assert!(
        not_object.starts_with("Failed lease=false secret settings are not a JSON object: ")
            && not_object.ends_with(" kind=4 material=\"\""),
        "{not_object}"
    );
    resolved[4] = "NOT-AN-OBJECT".into();
    assert_eq!(
        resolved,
        serde_json::json!([
            format!("Ready lease=true  kind=0 material={VALUE:?} released=Ready lease=false "),
            format!("Failed lease=false secret file:{unset} cannot resolve: {} kind=1 material=\"\"", std::fs::File::open(&unset).expect_err("the missing fixture is missing")),
            format!("Failed lease=false secret file:{empty} resolved to an EMPTY file; a secret must be non-empty (fail-closed) kind=4 material=\"\""),
            "Failed lease=false secret module 'file' requires settings.path naming the file (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`) kind=4 material=\"\"",
            "NOT-AN-OBJECT",
        ])
    );
    assert_eq!(linked["release_unknown"], "Refused lease=false ");
    assert_eq!(linked["refresh"], "Ready lease=false ");
    assert_eq!(linked["tick"], "Ready lease=false  next=0");
    assert_eq!(linked["close"], "Ready lease=false ");
}

/// RED: the door asked for as another kind is refused, by either origin.
#[test]
fn a_wrong_kind_is_refused() {
    let d = dispatcher();
    let row = LinkedRow::of(busbar_secret_file::door::door).expect("the linked row states");
    let err =
        load_linked::<Export>(&row, bind(&d)).expect_err("a secret door is not an export door");
    let said = format!("{err:?}");
    assert!(said.contains("Secret") || said.contains("Kind"), "{said}");

    let as_export = stating(&[
        (1, KindCode::Export as u32),
        (2, busbar_contract::abi::export::ABI_VERSION),
    ]);
    let err = load_dropped::<Export>(&cdylib(), &as_export, bind(&d))
        .expect_err("the dropped-in secret door is not an export door");
    assert!(!matches!(err, LoadError::ManifestKind { .. }), "{err:?}");
}

/// RED: a manifest whose statement disagrees with what is asked is refused before `dlopen`; one
/// stating 1.5.5's secret ABI (v1) is refused (ABI-b6).
#[test]
fn a_statement_mismatch_is_refused() {
    let d = dispatcher();
    let err = load_dropped::<Secret>(
        &cdylib(),
        &stating(&[(1, KindCode::Export as u32)]),
        bind(&d),
    )
    .expect_err("a manifest stating another kind is refused");
    assert!(matches!(err, LoadError::ManifestKind { .. }), "{err:?}");

    let err = load_dropped::<Secret>(
        &cdylib(),
        &stating(&[(2, secret::ABI_VERSION - 1)]),
        bind(&d),
    )
    .expect_err("a manifest stating 1.5.5's secret ABI is refused");
    assert!(matches!(err, LoadError::ManifestKindAbi { .. }), "{err:?}");

    let err = load_dropped::<Secret>(&cdylib(), &stating(&[(0, MECHANISM_VERSION + 1)]), bind(&d))
        .expect_err("a manifest stating another mechanism is refused");
    assert!(
        matches!(err, LoadError::ManifestMechanism { .. }),
        "{err:?}"
    );
}
