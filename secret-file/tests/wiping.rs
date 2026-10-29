// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every heap block the source frees while it resolves a file must have been wiped first (the
//! credential chip, row 6: host-owned secret bytes): the bytes read, the read chunk, a buffer the
//! read outgrew, and the resolved value once its answer drops (the SDK has written it into the
//! host's buffer by then). This test binary installs a global allocator whose `dealloc` scans the
//! block being freed for a canary while armed. It is its own binary so the crate's
//! `forbid(unsafe_code)` does not apply to the allocator wrapper.
//!
//! Not covered, and not claimable: the kernel's page cache holds the file's bytes; they are the
//! operator's file, not this source's memory.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

const CANARY: &[u8] = b"CANARY-FILE-VALUE-7a2c";

static ARMED: AtomicBool = AtomicBool::new(false);
static SAW: AtomicBool = AtomicBool::new(false);

/// A naive byte search; allocates nothing.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

struct Scanning;

// SAFETY: every call forwards unchanged to `System`; `dealloc` only reads the block it is about to
// free (and `realloc` is the trait's default, so a grown block's old storage also reaches `dealloc`).
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            if contains(block, CANARY) {
                SAW.store(true, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// RED while `resolve` answered a plain `Vec<u8>`: the resolved value was freed unwiped.
#[test]
fn a_resolved_file_is_wiped_before_it_is_freed() {
    let at = std::env::temp_dir().join(format!("busbar-secret-file-wiping-{}", std::process::id()));
    std::fs::write(&at, CANARY).expect("the canary file");
    let mut settings = serde_json::Map::new();
    settings.insert("path".into(), at.to_str().expect("utf-8 path").into());

    ARMED.store(true, Ordering::SeqCst);
    let resolved = busbar_secret_file::resolve(&settings);
    assert!(resolved.is_ok(), "the file resolves");
    drop(resolved);
    ARMED.store(false, Ordering::SeqCst);

    let _ = std::fs::remove_file(&at);
    assert!(
        !SAW.load(Ordering::SeqCst),
        "a resolved value reached the allocator unwiped"
    );
}
