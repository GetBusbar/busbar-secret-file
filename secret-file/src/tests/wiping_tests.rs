// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe initialized read-buffer prefixes across growth, failure and resolved-value drop.

#[allow(unsafe_code)]
#[path = "wipe_probe.rs"]
mod probe;

use busbar_contract::abi::sdk::cred::Held;
use busbar_contract::secret::SecretErrorKind;

const VALUE: &[u8] = b"CANARY-FILE-VALUE-7a2c";

/// The read seam's observer: registers every buffer `read_bounded` shows it as file bytes.
fn watch(bytes: &[u8]) {
    probe::watch("file bytes", bytes);
}

#[test]
fn a_resolved_file_is_wiped_before_it_is_freed() {
    let at = std::env::temp_dir().join(format!("busbar-secret-file-wiping-{}", std::process::id()));
    std::fs::write(&at, VALUE).expect("the canary file");
    let settings = serde_json::json!({ "path": at.to_str().unwrap() })
        .as_object()
        .unwrap()
        .clone();

    let observed = probe::Probe::start();
    let path = super::reference_path(&settings).expect("the reference names its path");
    let resolved = super::resolve_path(path, watch).expect("the file resolves");
    assert!(
        resolved == Held::new(VALUE.to_vec()),
        "the actual file resolves"
    );
    drop(resolved);
    let report = observed.finish();

    std::fs::remove_file(at).unwrap();
    report.assert_wiped(&["file bytes"]);
}

struct ReadThen {
    left: usize,
    fail: bool,
}

impl std::io::Read for ReadThen {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return if self.fail {
                Err(std::io::ErrorKind::TimedOut.into())
            } else {
                Ok(0)
            };
        }
        let n = self.left.min(out.len());
        out[..n].fill(b's');
        self.left -= n;
        Ok(n)
    }
}

#[test]
fn growing_reads_wipe_every_old_buffer_and_the_resolved_value() {
    let observed = probe::Probe::start();
    let resolved = super::read_bounded(
        &mut ReadThen {
            left: 40_000,
            fail: false,
        },
        0,
        "/growing",
        watch,
    )
    .expect("the reader resolves");
    assert!(resolved == Held::new(vec![b's'; 40_000]));
    drop(resolved);
    let report = observed.finish();
    // The chunk plus at least two generations of the growing buffer: one initialized buffer
    // was outgrown (the chunk and one buffer alone register two).
    assert!(
        report.allocations() > 2,
        "the read actually outgrew an initialized buffer"
    );
    report.assert_wiped(&["file bytes"]);
}

#[test]
fn a_read_failure_wipes_all_bytes_already_read() {
    let observed = probe::Probe::start();
    let error = super::read_bounded(
        &mut ReadThen {
            left: 40_000,
            fail: true,
        },
        0,
        "/failing",
        watch,
    )
    .err()
    .expect("the reader fails after yielding material");
    assert_eq!(error.kind, SecretErrorKind::Unavailable);
    drop(error);
    let report = observed.finish();
    assert!(
        report.allocations() > 2,
        "the failed read also exercised growth"
    );
    report.assert_wiped(&["file bytes"]);
}

#[test]
fn a_read_past_the_bound_wipes_all_bytes_already_read() {
    let observed = probe::Probe::start();
    let error = super::read_bounded(
        &mut ReadThen {
            left: super::MAX + 1,
            fail: false,
        },
        0,
        "/over-bound",
        watch,
    )
    .err()
    .expect("the reader is refused at the bound");
    assert_eq!(error.kind, SecretErrorKind::Invalid);
    drop(error);
    observed.finish().assert_wiped(&["file bytes"]);
}
