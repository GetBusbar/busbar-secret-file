// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the `file` source on the secret kind's table (`busbar_contract::abi::secret`). The nine
//! lifecycle slots are the SDK's generic lifecycle (`lifecycle: life(File)`, [`Life`]), and
//! `resolve` and `check` are [`SafeSlot`]s — no `unsafe` in this crate.

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{
    Rewrite, Statement, REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE,
};
use busbar_contract::abi::sdk::cred::resolved;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::secret::{failed, settings_of, takes_no_settings};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, CheckIn, ResolveIn, ResolveOut};

/// A rewrite naming this source by its word ([`crate::WORD`]), in `class`, carrying `to`.
const fn rewrite(class: u32, to: &'static str) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(crate::WORD),
        to: abi_str(to),
    }
}

/// The names config gives this source (the Statement's `rewrites`, the sugar each secret plugin
/// spells itself): the module alias (`module: file`), the reference sugar (`{ file: X }` becomes
/// `{ module: file, settings: { path: X } }`), what a refusal names its value, and its core role.
const REWRITES: &[Rewrite] = &[
    rewrite(REWRITE_ALIAS, ""),
    rewrite(REWRITE_SUGAR, crate::KEY),
    rewrite(REWRITE_SUGAR_NAMES, "the file to read"),
    rewrite(REWRITE_SUGAR_ROLE, "path"),
];

/// The settings accepted by this plugin's lifecycle parser.
const SETTINGS_SCHEMA: busbar_contract::abi::mechanism::call::Blob =
    busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"));

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, and
/// the names config gives it.
pub const STATEMENT: Statement = Statement {
    settings_schema: SETTINGS_SCHEMA,
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(crate::NAME, env!("CARGO_PKG_VERSION"), 16)
};

/// One instance: every reference names its own path, so there is nothing to hold.
#[derive(Debug)]
pub struct File;

impl Life for File {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        takes_no_settings(settings, crate::WORD, crate::NAMES).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::validate(settings).map(|()| File)
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Self::validate(settings).map(|()| Refreshed::default())
    }
}

/// `resolve`: READY with the file's bytes in the host's buffer, FAILED with its code and text.
pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<File>;
    fn call(
        instance: Instance<'_, Held<File>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        let settings = input.field(|i| &i.settings).bytes();
        match settings_of(settings).and_then(|s| crate::resolve(&s)) {
            Ok(material) => resolved(input, &mut out, material),
            Err(e) => failed(&mut out, e),
        }
    }
}

/// Judge reference syntax without opening an instance or reading the filesystem.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = OutHead;
    type State = Held<File>;

    fn call(
        _: Instance<'_, Held<File>>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let settings = input.field(|i| &i.settings).bytes();
        match settings_of(settings).and_then(|s| crate::reference_path(&s).map(|_| ())) {
            Ok(()) => Outcome::Ready,
            Err(error) => out.fail(Refusal::failed(error.message)),
        }
    }
}

mod table {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: super::STATEMENT,
        lifecycle: life(super::File),
        kind_ops: {
            resolve: super::Safe<super::Resolve>,
            check: super::Safe<super::Check>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
