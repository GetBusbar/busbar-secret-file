// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHORTHAND THIS SOURCE ANSWERS TO, as the host reads it (busbar audit contract-admin #10,
//! Law 0/1: core names kinds, never instances): the `{ file: X }` shorthand is this plugin's own
//! declaration, so its Statement states the word, the settings key the value lands under and what
//! a refusal says the value names. The kernel reads these off the loaded Statements and spells
//! none of them. Read through the loader's linked row, at the busbar commit this repo pins.

use busbar_contract::abi::mechanism::door::{REWRITE_SUGAR, REWRITE_SUGAR_NAMES};
use busbar_contract::abi::mechanism::rendering::read;
use busbar_plugin_loader::dispatch::{LinkedRow, LoadedDoor};

/// This crate's own door, as the loader names a compiled-in one.
#[allow(unused_unsafe)]
fn loaded() -> LoadedDoor {
    // SAFETY: `door` is this crate's own `plugin_door!` entry.
    unsafe { LoadedDoor::from_raw(busbar_secret_file::door) }
}

/// The rewrites the linked door's Statement states, `(class, from, to)`.
fn rewrites() -> Vec<(u32, String, String)> {
    let row = LinkedRow::of_loaded(loaded()).expect("the linked door states its Statement");
    read(&row.statement)
        .expect("the Statement rendering reads back")
        .rewrites
}

#[test]
fn the_statement_declares_its_shorthand_and_the_settings_key_it_lands_under() {
    let r = rewrites();
    assert!(
        r.contains(&(REWRITE_SUGAR, "file".to_string(), "path".to_string())),
        "the `{{ file: X }}` shorthand must state its settings key `path`: {r:?}"
    );
}

#[test]
fn the_statement_declares_what_the_shorthand_value_names() {
    let r = rewrites();
    assert!(
        r.contains(&(
            REWRITE_SUGAR_NAMES,
            "file".to_string(),
            "the file to read".to_string()
        )),
        "the `{{ file: X }}` shorthand must state what its value names: {r:?}"
    );
}
