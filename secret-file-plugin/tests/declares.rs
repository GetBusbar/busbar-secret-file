// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DISK NEED, as the host reads it (THE DESIGN §11.11 R4, as the OWNER amended it 2026-10-13):
//! the `file` source reads the local disk, so its declares document states `disk`, the one fact the
//! host runs its `resolve` on the bounded disk lane by, at config time only. Read through the
//! loader's ONE reader of a declares document, at the busbar commit this repo pins.

use busbar_plugin_loader::dispatch::{LinkedRow, LoadedDoor};
use busbar_plugin_loader::sign::Declares;

/// This crate's own door, as the loader names a compiled-in one.
#[allow(unused_unsafe)]
fn loaded() -> LoadedDoor {
    // SAFETY: `door` is this crate's own `plugin_door!` entry.
    unsafe { LoadedDoor::from_raw(busbar_secret_file::door) }
}

/// RED (audit pinned secret-file #1): the declares document states the disk need.
#[test]
fn the_declares_document_states_the_disk_need() {
    let row = LinkedRow::of_loaded(loaded()).expect("the linked door states its Statement");
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("the Statement rendering reads back");
    let document = busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes)
        .expect("the Statement carries the declares document");
    assert_eq!(
        document,
        &include_bytes!("../../secret-file/declares.json")[..]
    );
    let declares = Declares::from_declares_json(document).expect("the declares document reads");
    assert!(
        declares.disk,
        "the file source reads the disk: its declares document must state `disk`"
    );
}
