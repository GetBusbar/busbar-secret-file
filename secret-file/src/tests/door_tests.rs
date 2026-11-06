// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rewrites this source states (its Statement's `rewrites`), read from the shipped
//! [`super::STATEMENT`], and `rewrite`, the helper each is built with, called at run time.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{
    Rewrite, REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE,
};

/// The four rewrites the source must state, `(class, from, to)`.
const EXPECTED: [(u32, &str, &str); 4] = [
    (REWRITE_ALIAS, "file", ""),
    (REWRITE_SUGAR, "file", "path"),
    (REWRITE_SUGAR_NAMES, "file", "the file to read"),
    (REWRITE_SUGAR_ROLE, "file", "path"),
];

/// The text an `AbiStr` built from a `'static str` names.
#[allow(unsafe_code)]
fn text(s: AbiStr) -> &'static str {
    assert!(!s.is_absent(), "a rewrite string is present");
    // SAFETY: every `AbiStr` here is `abi_str` over a `'static str`.
    std::str::from_utf8(unsafe { s.bytes() }).expect("UTF-8")
}

/// The rewrites the shipped Statement states.
#[allow(unsafe_code)]
fn stated() -> &'static [Rewrite] {
    let s = super::STATEMENT;
    // SAFETY: `rewrites`/`rewrites_len` are the static `REWRITES` slice's pointer and length.
    unsafe { std::slice::from_raw_parts(s.rewrites, s.rewrites_len) }
}

fn triple(r: &Rewrite) -> (u32, &'static str, &'static str) {
    assert_eq!(r._reserved, 0, "padding is zero");
    (r.class, text(r.from), text(r.to))
}

#[test]
fn the_statement_states_the_alias_the_sugar_its_names_and_its_role() {
    let stated: Vec<_> = stated().iter().map(triple).collect();
    assert_eq!(stated, EXPECTED);
}

#[test]
fn rewrite_builds_each_stated_rewrite_naming_the_source_by_its_word() {
    for (class, from, to) in EXPECTED {
        assert_eq!(triple(&super::rewrite(class, to)), (class, from, to));
    }
}
