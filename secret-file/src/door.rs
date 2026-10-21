// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the `file` source on the secret kind's table (`busbar_contract::abi::secret`), the nine
//! lifecycle slots the SDK's generic lifecycle (`lifecycle: life(File)`, [`Life`]) and `resolve` a
//! [`SafeSlot`] — no `unsafe` in this crate.
//!
//! * `validate`, `open`, `refresh` — the source holds no settings and no state: any settings object
//!   opens it.
//! * `resolve` — a reference's `{ path: PATH }` to the file's bytes, READY under a lease (the
//!   SDK's [`Held`] leases, zeroed on release), or FAILED with its `ERROR_KIND_*` and its text. It
//!   never pends: the read is the disk's, and the host runs it on its bounded disk lane at config
//!   time only (the declared disk need, THE DESIGN §11.11 R4).
//! * `release`, `close`, `cancel`, `tick`, `retire`, `drive` — the SDK's.

use busbar_contract::abi::mechanism::call::{Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{
    Rewrite, Statement, REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut, ERROR_KIND_UNSET};

use crate::{error_kind, settings_of};

/// A rewrite naming this source by its word ([`crate::WORD`]), in `class`, carrying `to`.
const fn rewrite(class: u32, to: &'static str) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(crate::WORD),
        to: abi_str(to),
    }
}

/// The names config gives this source (THE DESIGN §2, the Statement's `rewrites`; busbar step 2c,
/// the sugar each secret plugin spells itself): the module alias (`module: file`), the
/// reference sugar (`{ file: X }` becomes `{module: file, settings: {path: X}}`), what a
/// refusal names its value, and its core role.
const REWRITES: &[Rewrite] = &[
    rewrite(REWRITE_ALIAS, ""),
    rewrite(REWRITE_SUGAR, crate::KEY),
    rewrite(REWRITE_SUGAR_NAMES, "the file to read"),
    rewrite(REWRITE_SUGAR_ROLE, "path"),
];

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document (BUSBAR-1.6.0.md l.246).
    /// This source reads the disk (`"disk": true`), so the host resolves it only at config time, on
    /// its bounded disk lane, never from a request path (l.1464-1469, R4, OWNER 2026-10-13).
    EXTENSIONS: [(
        busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
        include_bytes!("../declares.json")
    )]
);

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, the
/// names config gives it, and its `declares` document.
const STATEMENT: Statement = {
    let mut s = statement(crate::NAME, env!("CARGO_PKG_VERSION"), 16).with_rewrites(REWRITES);
    s.extensions = EXTENSIONS;
    s
};

/// One instance: every reference names its own path, so there is nothing to hold.
#[derive(Debug)]
pub struct File;

impl Life for File {
    const CANCEL: u32 = cancel::ABORTED;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(File)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// `resolve`: READY with the file's bytes under a lease, FAILED with its code and text.
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
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let settings = input.settings().bytes();
        match settings_of(settings).and_then(|s| crate::resolve(&s)) {
            Ok(material) => {
                out.lease_secret(|o| &o.secret, held.leases(), material, BLOB_OCTETS);
                out.set(|o| &o.error_kind, ERROR_KIND_UNSET);
                Outcome::Ready
            }
            Err(e) => {
                out.set(|o| &o.error_kind, error_kind(e.kind));
                out.fail(Refusal::failed(e.message))
            }
        }
    }
}

mod table {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: super::STATEMENT,
        lifecycle: life(super::File),
        kind_ops: { resolve: super::Safe<super::Resolve> },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::{door, MACRO_DOOR};
