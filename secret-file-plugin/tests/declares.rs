// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DISK NEED, as the host reads it (THE DESIGN §11.11 R4, as the OWNER amended it 2026-10-13):
//! the `file` source reads the local disk, so its declares document states `disk`, the one fact the
//! host runs its `resolve` on the bounded disk lane by, at config time only. Read through the
//! loader's ONE reader of a declares document, at the busbar commit this repo pins.

use busbar_plugin_loader::sign::Declares;

/// RED (audit pinned secret-file #1): the declares document states the disk need.
#[test]
fn the_declares_document_states_the_disk_need() {
    let declares = Declares::from_declares_json(include_bytes!("../../secret-file/declares.json"))
        .expect("the declares document reads");
    assert!(
        declares.disk,
        "the file source reads the disk: its declares document must state `disk`"
    );
}
