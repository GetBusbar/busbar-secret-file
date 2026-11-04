// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The declares document states the disk need used for host scheduling of file secret resolution.

use busbar_plugin_loader::sign::Declares;

#[test]
fn the_declares_document_states_the_disk_need() {
    let declares = Declares::from_declares_json(include_bytes!("../../secret-file/declares.json"))
        .expect("the declares document reads");
    assert!(
        declares.disk,
        "the file source reads the disk: its declares document must state `disk`"
    );
}
