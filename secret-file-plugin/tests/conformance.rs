// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FILE PLUGIN, BOTH DOORS, ONE TABLE** — the `file` secret source's linked + dropped-in
//! conformance on the secret kind's memory ABI, run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, through the
//! loader's `load_linked`) and DROPPED IN (the freshly built cdylib named by
//! `BUSBAR_PLUGIN_CDYLIB`, through `load_dropped`). Each is bound to a real dispatcher and driven
//! over the same script through the secret kind's table, and the two transcripts must be equal;
//! the resolved value is read out of the HOST'S buffer the call lent, under no lease. An absent
//! cdylib fails the test: this file is the dropped-in door's proof and never skips.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::MECHANISM_VERSION;
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, Bind, Called,
    DispatchConfig, Dispatcher, Frame, LinkedRow, LoadError, Plugin, NO_BLOB,
};

/// The value the present file holds; the transcript carries it only as the resolved material.
const VALUE: &str = "s3cr3t-file-conformance";

/// The three fixture paths (present, empty, missing), under one per-process temp directory.
fn fixtures() -> (String, String, String) {
    static FILES: std::sync::OnceLock<(String, String, String)> = std::sync::OnceLock::new();
    FILES
        .get_or_init(|| {
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
        })
        .clone()
}

/// Load the actual plugin image built beside this integration-test executable.
fn cdylib() -> PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .expect("set BUSBAR_PLUGIN_CDYLIB to the freshly built secret-file cdylib");
    assert!(
        path.is_absolute() && path.is_file(),
        "actual secret-file cdylib required: {}",
        path.display()
    );
    path
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

// Capture the public envelope boundary, including plugin log records, independently of kit
// canary globals. Every production bind in this test binary uses this sink.
#[derive(Default)]
struct AuditSink(std::sync::Mutex<Vec<Vec<u8>>>);
impl AuditSink {
    fn hear(&self, bytes: &[u8]) {
        for credential in [VALUE.as_bytes(), b"sk-conformance".as_slice()] {
            assert!(
                !bytes
                    .windows(credential.len())
                    .any(|part| part == credential),
                "a configured credential crossed the envelope boundary"
            );
        }
        self.0
            .lock()
            .expect("envelope audit lock")
            .push(bytes.to_vec());
    }
}
impl busbar_plugin_loader::dispatch::EnvelopeSink for AuditSink {
    fn metric(&self, metric: busbar_plugin_loader::dispatch::Metric<'_>) {
        for label in metric.labels {
            self.hear(label);
        }
    }
    fn diag(&self, diagnostic: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        self.hear(diagnostic.name);
        self.hear(diagnostic.text);
    }
    fn dropped(&self, _: busbar_plugin_loader::dispatch::Dropped) {}
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("file"),
        max_inflight_cap: 64,
        sink: Arc::new(AuditSink::default()),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
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
    for credential in [VALUE, "sk-conformance"] {
        assert!(
            !text.contains(credential),
            "an error exposed a fixture credential"
        );
    }
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn crossings(p: &Plugin<Secret>) -> (u64, u64) {
    use std::sync::atomic::Ordering::SeqCst;
    let total = p.inner.crossings.load(SeqCst);
    let resumes = p.inner.resumes.load(SeqCst);
    (total - resumes, resumes)
}

fn expect_crossings(p: &Plugin<Secret>, before: (u64, u64), expected: u64) {
    let after = crossings(p);
    assert_eq!(
        after.0 - before.0,
        expected,
        "exact actual first-entry crossings"
    );
    assert_eq!(after.1 - before.1, 0, "file never pends or resumes");
}

fn counted_call<
    I: busbar_plugin_loader::dispatch::InFrame,
    O: busbar_plugin_loader::dispatch::OutFrame,
>(
    p: &Plugin<Secret>,
    slot: u32,
    frame: &mut Frame<I, O>,
) -> Called {
    use busbar_contract::abi::mechanism::call::Outcome;
    let before = crossings(p);
    let answer = p.call(slot, frame);
    let host_refusal = (slot == lc::OPEN || slot == secret::slot::RESOLVE)
        && matches!(answer.outcome, Outcome::Refused | Outcome::Fault);
    expect_crossings(p, before, u64::from(!host_refusal));
    answer
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
    spelled(&counted_call(p, lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Secret>) -> String {
    open_with(p, NO_BLOB)
}

fn open_with(p: &Plugin<Secret>, settings: Blob) -> String {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings,
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
    spelled(&counted_call(p, lc::OPEN, &mut f))
}

fn refresh(p: &Plugin<Secret>) -> String {
    refresh_with(p, NO_BLOB)
}

fn refresh_with(p: &Plugin<Secret>, settings: Blob) -> String {
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings,
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    spelled(&counted_call(p, lc::REFRESH, &mut f))
}

/// One resolve into a zeroed host buffer of `cap` bytes: its answer, its error kind, the material
/// it wrote (read out of the host's buffer, which the answer must name) and the `needed` a short
/// answer states.
fn resolve_into(p: &Plugin<Secret>, settings: &str, cap: usize) -> String {
    let mut buf = vec![0_u8; cap];
    let mut f = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
            secret_buf: buf.as_mut_ptr(),
            secret_cap: buf.len(),
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
            needed: 0,
        },
    );
    let c = counted_call(p, secret::slot::RESOLVE, &mut f);
    assert_eq!(c.lease, 0, "secret material never creates a lease");
    let blob = f.out.secret;
    if c.outcome == busbar_contract::abi::mechanism::call::Outcome::Ready {
        assert_eq!(blob.fmt, busbar_contract::abi::mechanism::call::BLOB_OCTETS);
        assert_ne!(
            blob.flags & busbar_contract::abi::mechanism::call::BLOB_SECRET,
            0
        );
    }
    if c.outcome != busbar_contract::abi::mechanism::call::Outcome::Ready {
        assert!(
            blob.ptr.is_null() && blob.len == 0,
            "a refusal returned material"
        );
        assert!(
            buf.iter().all(|byte| *byte == 0),
            "a refusal wrote secret bytes into the host buffer"
        );
    }
    let material = if blob.ptr.is_null() || blob.len == 0 {
        String::new()
    } else {
        assert_eq!(
            blob.ptr,
            buf.as_ptr(),
            "a READY value is in the host's buffer"
        );
        String::from_utf8_lossy(&buf[..blob.len]).into_owned()
    };
    buf.fill(0);
    let needed = if f.out.needed == 0 {
        String::new()
    } else {
        format!(" needed={}", f.out.needed)
    };
    format!(
        "{} kind={} material={material:?}{needed}",
        spelled(&c),
        f.out.error_kind
    )
}

/// [`resolve_into`] the host's first buffer.
fn resolve(p: &Plugin<Secret>, settings: &str) -> String {
    resolve_into(p, settings, secret::FIRST_SECRET_CAP)
}

fn release(p: &Plugin<Secret>, lease: u64) -> String {
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    spelled(&counted_call(p, lc::RELEASE, &mut f))
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
    let c = counted_call(p, lc::TICK, &mut f);
    format!("{} next={}", spelled(&c), f.out.next_tick_ns)
}

fn close(p: &Plugin<Secret>) -> String {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    spelled(&counted_call(p, lc::CLOSE, &mut f))
}

/// What one door does, as one comparable transcript.
fn transcript(p: &Plugin<Secret>) -> serde_json::Value {
    let before_facts = crossings(p);
    let facts = (
        p.name().to_owned(),
        format!("{:?}", p.kind()),
        p.max_inflight(),
    );
    expect_crossings(p, before_facts, 0);
    let (set, empty, unset) = fixtures();
    let validated = [
        validate(p, ""),
        validate(p, "{}"),
        validate(p, "[1]"),
        validate(p, r#"{"path":"/x"}"#),
    ];
    let unopened = resolve(p, &format!(r#"{{"path":"{set}"}}"#));
    let open_refused = open_with(p, json(br#"{"path":"/x"}"#));
    let (opened, opened_again) = (open(p), open(p));
    let resolved: Vec<String> = [
        format!(r#"{{"path":"{set}"}}"#),
        format!(r#"{{"path":"{unset}"}}"#),
        format!(r#"{{"path":"{empty}"}}"#),
        r#"{"path":"  "}"#.to_string(),
        "[1]".to_string(),
        format!(r#"{{"path":"{set}","key":"X"}}"#),
    ]
    .iter()
    .map(|s| resolve(p, s))
    .collect();

    let short = resolve_into(p, &format!(r#"{{"path":"{set}"}}"#), VALUE.len() - 1);
    serde_json::json!({
        "name": facts.0,
        "kind": facts.1,
        "max_inflight": facts.2,
        "validate": validated,
        "resolve_unopened": unopened,
        "open_refused": open_refused,
        "open": opened,
        "open_again": opened_again,
        "resolve": resolved,
        "resolve_short": short,
        "release_unknown": release(p, 42),
        "refresh_refused": refresh_with(p, json(br#"{"path":"/x"}"#)),
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
                "path".to_string()
            ),
            (
                busbar_contract::abi::mechanism::door::REWRITE_SUGAR_NAMES,
                "file".to_string(),
                "the file to read".to_string()
            ),
            (
                busbar_contract::abi::mechanism::door::REWRITE_SUGAR_ROLE,
                "file".to_string(),
                "path".to_string()
            ),
        ],
        "the Statement names the source by its module alias and its reference sugar, the settings key that sugar's value lands under, what a refusal says it names and its role"
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
            "Failed lease=false secret module 'file' takes no settings; remove settings.path (each reference names its file in its own settings.path)",
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
            format!("Ready lease=false  kind=0 material={VALUE:?}"),
            format!("Failed lease=false secret file:{unset} cannot resolve: {} kind=1 material=\"\"", std::fs::File::open(&unset).expect_err("the missing fixture is missing")),
            format!("Failed lease=false secret file:{empty} resolved to an EMPTY file; a secret must be non-empty (fail-closed) kind=4 material=\"\""),
            "Failed lease=false secret module 'file' requires settings.path naming the file (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`) kind=4 material=\"\"",
            "NOT-AN-OBJECT",
            "Failed lease=false secret module 'file' does not take settings.key; a reference names only settings.path (fail-closed) kind=4 material=\"\"",
        ])
    );
    assert_eq!(
        linked["resolve_short"],
        format!(
            "Failed lease=false  kind=0 material=\"\" needed={}",
            VALUE.len()
        ),
        "a value over the host's buffer is the short-buffer answer"
    );
    assert_eq!(
        linked["release_unknown"],
        format!(
            "Refused lease=false {}",
            busbar_contract::abi::sdk::life::NO_SUCH_LEASE
        ),
        "a release of a lease the instance does not hold is refused naming why (the SDK's)"
    );
    assert_eq!(
        linked["open_refused"],
        "Failed lease=false secret module 'file' takes no settings; remove settings.path (each reference names its file in its own settings.path)",
        "open refuses what validate refuses"
    );
    assert_eq!(
        linked["refresh_refused"],
        "Failed lease=false secret module 'file' takes no settings; remove settings.path (each reference names its file in its own settings.path)",
        "refresh refuses what validate refuses"
    );
    assert_eq!(linked["refresh"], "Ready lease=false ");
    assert_eq!(linked["tick"], "Ready lease=false  next=0");
    assert_eq!(linked["close"], "Ready lease=false ");
}

#[test]
fn a_file_above_the_answer_bound_answers_failed_naming_the_path() {
    use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
    let dir = std::env::temp_dir().join(format!(
        "busbar-secret-file-conformance-bound-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let over = dir.join("over");
    let f = std::fs::File::create(&over).expect("the over-bound fixture");
    f.set_len(HARD_MAX_BYTES + 1).expect("its length");
    drop(f);
    let over = over.to_string_lossy().into_owned();
    let d = dispatcher();
    for p in [linked(&d), dropped(&d)] {
        assert_eq!(open(&p), "Ready lease=false ");
        assert_eq!(
            resolve(&p, &format!(r#"{{"path":"{over}"}}"#)),
            format!(
                "Failed lease=false secret file:{over} cannot resolve: the file is larger than \
                 {HARD_MAX_BYTES} bytes, the most a secret may hold (fail-closed) kind=4 \
                 material=\"\""
            )
        );
        assert_eq!(close(&p), "Ready lease=false ");
    }
    std::fs::remove_file(&over).ok();
}

#[test]
fn a_manifest_stating_another_mechanism_is_refused() {
    let d = dispatcher();
    let err = load_dropped::<Secret>(&cdylib(), &stating(&[(0, MECHANISM_VERSION + 1)]), bind(&d))
        .expect_err("a manifest stating another mechanism is refused");
    assert!(
        matches!(err, LoadError::ManifestMechanism { .. }),
        "{err:?}"
    );
}

#[test]
fn reference_check_is_pure_and_refuses_bad_settings_through_both_doors() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::secret::CheckIn;

    let missing = std::env::temp_dir().join(format!(
        "busbar-secret-file-check-missing-{}",
        std::process::id()
    ));
    assert!(!missing.exists());
    let valid = serde_json::json!({"path": missing}).to_string();
    let d = dispatcher();
    for p in [linked(&d), dropped(&d)] {
        for (settings, expected, reason) in [
            (valid.as_str(), Outcome::Ready, ""),
            ("{}", Outcome::Failed, "requires settings.path"),
            (
                r#"{"path":"  "}"#,
                Outcome::Failed,
                "requires settings.path",
            ),
            (r#"{"path":7}"#, Outcome::Failed, "requires settings.path"),
            ("[1]", Outcome::Failed, "not a JSON object"),
            (
                r#"{"path":"/x","key":"X"}"#,
                Outcome::Failed,
                "does not take settings.key",
            ),
        ] {
            let mut reason_buf = [0_u8; 1024];
            let mut frame: Frame<CheckIn, OutHead> = Frame::new(
                CheckIn {
                    head: in_head(),
                    settings: json(settings.as_bytes()),
                    err_buf: reason_buf.as_mut_ptr(),
                    err_cap: reason_buf.len(),
                },
                out_head(),
            );
            let called = counted_call(&p, secret::slot::CHECK, &mut frame);
            assert_eq!(called.outcome, expected, "{settings}");
            assert_eq!(called.lease, 0);
            if expected == Outcome::Failed {
                let text = std::str::from_utf8(called.error.as_deref().expect("a reason"))
                    .expect("UTF-8 reason");
                assert!(text.contains(reason), "{text}");
                assert_eq!(frame.out.error.ptr, reason_buf.as_ptr());
                assert_eq!(&reason_buf[..frame.out.error.len], text.as_bytes());
            } else {
                assert!(called.error.as_deref().unwrap_or_default().is_empty());
            }
        }
    }
}

#[test]
fn repeated_resolution_and_refresh_keep_material_until_close() {
    let (set, _, _) = fixtures();
    let settings = serde_json::json!({"path": set}).to_string();
    let expected = format!("Ready lease=false  kind=0 material={VALUE:?}");
    let d = dispatcher();
    for p in [linked(&d), dropped(&d)] {
        assert_eq!(open(&p), "Ready lease=false ");
        assert_eq!(resolve(&p, &settings), expected);
        assert_eq!(resolve(&p, &settings), expected);
        assert!(refresh_with(&p, json(b"[1]")).starts_with("Failed lease=false "));
        assert_eq!(
            resolve(&p, &settings),
            expected,
            "failed refresh preserves serving state"
        );
        assert_eq!(refresh(&p), "Ready lease=false ");
        assert_eq!(resolve(&p, &settings), expected);
        assert!(resolve(&p, r#"{"name":5}"#).ends_with(" kind=4 material=\"\""));
        assert_eq!(close(&p), "Ready lease=false ");
        assert!(
            resolve(&p, &settings).starts_with("Fault lease=false "),
            "a closed instance serves no material: the host refuses the resolve uncrossed"
        );
    }
}

#[test]
fn declared_connection_needs_and_requested_profile_match_actual_images() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE requires cargo test --release"
    );
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../secret-file/declares.json")).unwrap();
    assert!(declared
        .get("needs")
        .is_none_or(|needs| needs.as_array().is_some_and(Vec::is_empty)));
    for statement in [
        LinkedRow::of(busbar_secret_file::door::door)
            .unwrap()
            .statement,
        stated(),
    ] {
        assert!(busbar_contract::abi::mechanism::rendering::read(&statement)
            .unwrap()
            .needs
            .is_empty());
    }
}

#[test]
fn ticketed_resolves_preserve_material_flags_buffers_and_refusals() {
    use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome, BLOB_SECRET};
    struct Lending {
        settings: Vec<u8>,
        material: std::sync::Mutex<Vec<u8>>,
    }
    let (set, _, unset) = fixtures();
    let d = dispatcher();
    for p in [linked(&d), dropped(&d)] {
        let before_ready = crossings(&p);
        p.ready(&d, Duration::from_secs(30))
            .expect("the actual file door is ready");
        expect_crossings(&p, before_ready, u64::from(p.has_ready()));
        assert_eq!(open(&p), "Ready lease=false ");
        for (reference, cap, expected, kind, needed) in [
            (
                serde_json::json!({"path": set}).to_string(),
                VALUE.len(),
                Outcome::Ready,
                0,
                0,
            ),
            (
                serde_json::json!({"path": set}).to_string(),
                VALUE.len() - 1,
                Outcome::Failed,
                0,
                VALUE.len() as u64,
            ),
            (
                serde_json::json!({"path": unset}).to_string(),
                128,
                Outcome::Failed,
                secret::ERROR_KIND_NOT_FOUND,
                0,
            ),
            (
                "[1]".to_owned(),
                128,
                Outcome::Failed,
                secret::ERROR_KIND_INVALID,
                0,
            ),
            (
                r#"{"name":5}"#.to_owned(),
                128,
                Outcome::Failed,
                secret::ERROR_KIND_INVALID,
                0,
            ),
        ] {
            let lent = Arc::new(Lending {
                settings: reference.into_bytes(),
                material: std::sync::Mutex::new(vec![0; cap]),
            });
            let buffer = lent.material.lock().unwrap().as_mut_ptr();
            let frame = Frame::new(
                ResolveIn {
                    head: in_head(),
                    settings: json(&lent.settings),
                    secret_buf: buffer,
                    secret_cap: cap,
                },
                ResolveOut {
                    head: out_head(),
                    secret: NO_BLOB,
                    error_kind: 0,
                    _reserved: 0,
                    needed: 0,
                },
            );
            let before_resolve = crossings(&p);
            let ticket = d.mint(0).expect("an actual resolve ticket");
            let done = d
                .submit_lent(
                    &p,
                    ticket,
                    secret::slot::RESOLVE,
                    frame,
                    DeadlineClass::Call,
                    busbar_plugin_loader::dispatch::now_ns().saturating_add(30_000_000_000),
                    Arc::clone(&lent) as busbar_plugin_loader::dispatch::Lent,
                )
                .wait_done();
            d.recycle(ticket);
            expect_crossings(&p, before_resolve, 1);
            assert_eq!(done.outcome, expected);
            assert_eq!(done.lease, 0);
            let called = Called {
                outcome: done.outcome,
                error: done.error,
                lease: done.lease,
                recall: None,
            };
            let _ = spelled(&called);
            let frame = done.frame.expect("ticket returns the actual frame");
            assert_eq!(frame.out.error_kind, kind);
            assert_eq!(frame.out.needed, needed);
            let mut material = lent.material.lock().unwrap();
            if expected == Outcome::Ready {
                assert_eq!(frame.out.secret.ptr, buffer.cast_const());
                assert_eq!(frame.out.secret.len, VALUE.len());
                assert_eq!(&material[..], VALUE.as_bytes());
                assert_ne!(frame.out.secret.flags & BLOB_SECRET, 0);
            } else {
                assert!(frame.out.secret.ptr.is_null());
                assert_eq!(frame.out.secret.len, 0);
                assert_eq!(frame.out.secret.flags & BLOB_SECRET, 0);
                assert!(material.iter().all(|byte| *byte == 0));
            }
            material.fill(0);
        }
        assert_eq!(close(&p), "Ready lease=false ");
    }
    assert_eq!(d.stats().deadline_without_wake, 0);
}

#[test]
fn the_actual_dropped_image_is_distinct_from_the_linked_image() {
    let path = cdylib();
    let (dropped_door, dropped_ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&path)
            .expect("the actual dropped image loads")
            .expect("the image exports its actual door");
    let linked = busbar_secret_file::door::door();
    assert_ne!(
        dropped_door,
        std::ptr::from_ref(linked) as usize,
        "different physical doors"
    );
    assert_ne!(
        dropped_ops,
        linked.parts().ops as usize,
        "different physical operation tables"
    );
}

fn different_valid_statement(statement: &[u8]) -> Vec<u8> {
    let version = busbar_contract::abi::mechanism::rendering::read(statement)
        .unwrap()
        .version;
    assert!(!version.is_empty());
    let at = statement
        .windows(version.len())
        .position(|bytes| bytes == version.as_bytes())
        .expect("the actual version is present in its rendering");
    let mut changed = statement.to_vec();
    changed[at] = if changed[at] == b'9' { b'8' } else { b'9' };
    busbar_contract::abi::mechanism::rendering::read(&changed)
        .expect("a changed version remains a valid Statement rendering");
    changed
}

// These negative inputs retain this product's actual Statement and operation table. Only the
// numerical ABI/layout declaration or version string is changed; no plugin behavior is copied.
extern "C" fn metadata_door<const CASE: usize>(
) -> *const busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    static DOORS: [std::sync::OnceLock<usize>; 5] = [const { std::sync::OnceLock::new() }; 5];
    *DOORS[CASE].get_or_init(|| {
        let mut parts = busbar_secret_file::door::door().parts();
        let kind = busbar_contract::abi::mechanism::KindCode::Secret;
        match CASE {
            0 => parts.kind_abi = kind.abi_version() + 1,
            1 => parts.kind_abi = kind.abi_version().wrapping_sub(1),
            2 => parts.layout = kind.layout_fingerprint() ^ 1,
            3 => parts.layout = 0,
            4 => {
                // SAFETY: the actual product's immutable Statement and all nested ranges are static.
                let statement = unsafe { parts.statement.read_unaligned() };
                const OTHER: &str = "0.0.0-conformance-restated";
                parts.statement = Box::leak(Box::new(Statement {
                    version: busbar_contract::abi::mechanism::call::AbiStr {
                        ptr: OTHER.as_ptr(),
                        len: OTHER.len(),
                    },
                    ..statement
                }));
            }
            _ => unreachable!(),
        }
        // SAFETY: the actual product's full table and nested Statement ranges remain immutable
        // and static. Changed metadata is deliberately invalid and judged before any operation.
        let door = unsafe { Door::__from_parts(parts) };
        Box::into_raw(Box::new(door)) as usize
    }) as *const Door
}

fn metadata_image() -> std::path::PathBuf {
    let image = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("BUSBAR_PLUGIN_CDYLIB must name the freshly built actual image"),
    );
    assert!(image.is_absolute() && image.is_file());
    image
}

#[test]
fn the_actual_kind_abi_is_checked_by_pack_linked_and_dropped_origins() {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use busbar_plugin_loader::dispatch::LoadError;
    let kind = busbar_contract::abi::mechanism::KindCode::Secret;
    let host = kind.abi_version();
    assert_eq!(busbar_secret_file::door::door().parts().kind_abi, host);
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_file::door::door).expect("actual Statement");
    let _ = load_linked::<Secret>(&honest, bind(&d)).expect("honest linked twin");
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d))
        .expect("honest dropped twin");
    for (door, abi) in [
        (metadata_door::<0> as RawDoorFn, host + 1),
        (metadata_door::<1>, host.wrapping_sub(1)),
    ] {
        let want = LoadError::KindAbi {
            kind,
            door: abi,
            host,
        };
        let packed = busbar_plugin_loader::dispatch::load::rendering_of_raw(door)
            .expect_err("pack refuses another ABI");
        assert_eq!(packed, want);
        let linked = LinkedRow::of_raw(door)
            .and_then(|row| load_linked::<Secret>(&row, bind(&d)).map(|_| ()))
            .expect_err("linked refuses another ABI");
        assert_eq!(linked, want);
        assert!(linked.to_string().contains("rebuild"));
        let mut statement = honest.statement.clone();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Secret>(&metadata_image(), &statement, bind(&d))
                .map(|_| ())
                .err(),
            Some(LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
}

#[test]
fn the_actual_kind_layout_is_checked_under_honest_and_own_rows() {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use busbar_plugin_loader::dispatch::LoadError;
    let kind = busbar_contract::abi::mechanism::KindCode::Secret;
    let host = kind.layout_fingerprint();
    assert_eq!(busbar_secret_file::door::door().parts().layout, host);
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_file::door::door).unwrap();
    let _ = load_linked::<Secret>(&honest, bind(&d)).unwrap();
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d)).unwrap();
    for (door, stated) in [
        (metadata_door::<2> as RawDoorFn, host ^ 1),
        (metadata_door::<3>, 0),
    ] {
        let refusal = busbar_plugin_loader::dispatch::load::rendering_of_raw(door)
            .expect_err("pack refuses incompatible layout");
        let LoadError::KindLayout {
            kind: named,
            stated: said,
            host: read,
            ..
        } = &refusal
        else {
            panic!("{refusal:?}")
        };
        assert_eq!((*named, *said, *read), (kind, stated, host));
        assert!(refusal
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let row = LinkedRow {
            statement: honest.statement.clone(),
            door,
        };
        assert_eq!(
            load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
            Some(refusal.clone())
        );
        assert_eq!(
            LinkedRow::of_raw(door)
                .and_then(|row| load_linked::<Secret>(&row, bind(&d)).map(|_| ()))
                .err(),
            Some(refusal)
        );
    }
}

#[test]
fn the_actual_statement_matches_each_row_manifest_and_restated_version() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_file::door::door).unwrap();
    let _ = load_linked::<Secret>(&honest, bind(&d)).unwrap();
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d)).unwrap();
    let changed = different_valid_statement(&honest.statement);
    let row = LinkedRow {
        statement: changed.clone(),
        door: honest.door,
    };
    assert_eq!(
        load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Secret>(&metadata_image(), &changed, bind(&d))
            .map(|_| ())
            .err(),
        Some(LoadError::StatementMismatch)
    );
    let row = LinkedRow {
        statement: honest.statement,
        door: metadata_door::<4>,
    };
    assert_eq!(
        load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
        Some(LoadError::StatementMismatch)
    );
}

fn other_kind_is_refused<K: busbar_plugin_loader::dispatch::Kind>() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(Default::default());
    let row = LinkedRow::of(busbar_secret_file::door::door).unwrap();
    let want = LoadError::ManifestKind {
        stated: busbar_contract::abi::mechanism::KindCode::Secret,
        want: K::CODE,
    };
    assert_eq!(
        load_linked::<K>(&row, bind(&d)).map(|_| ()).err(),
        Some(want.clone())
    );
    assert_eq!(
        load_dropped::<K>(&metadata_image(), &row.statement, bind(&d))
            .map(|_| ())
            .err(),
        Some(want)
    );
}

#[test]
fn the_actual_image_is_refused_as_every_other_kind_through_both_origins() {
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::auth::Auth>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::export::Export>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::hook::Hook>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::plane::Plane>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::store::Store>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::transport::Transport>();
}
