// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the `file` source on the secret kind's table (`busbar_contract::abi::secret`), the nine
//! lifecycle slots the SDK's generic lifecycle (`lifecycle: life(File)`, [`Life`]) and `resolve` a
//! [`SafeSlot`] — no `unsafe` in this crate.
//!
//! * `validate`, `open`, `refresh` — the source holds no settings and no state: any settings object
//!   opens it.
//! * `resolve` — a reference's `{ path: PATH }` to the file's bytes, READY under a lease (the
//!   SDK's [`Held`] leases, zeroed on release), or FAILED with its `ERROR_KIND_*` and 1.5.5's text.
//!   It never pends.
//! * `release`, `close`, `cancel`, `tick`, `retire`, `drive` — the SDK's.

use busbar_contract::abi::mechanism::call::{Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement, REWRITE_ALIAS, REWRITE_SUGAR};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut, ERROR_KIND_UNSET};
use busbar_contract::secret_ref::SECRET_MODULE_FILE;

use crate::{error_kind, settings_of};

/// A rewrite naming this source by the `file` word, in `class`.
const fn word(class: u32) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(SECRET_MODULE_FILE),
        to: abi_str(""),
    }
}

/// The names config gives this source (THE DESIGN §2, the Statement's `rewrites`): the module alias
/// (`module: file`) and the reference sugar (`{ file: PATH }`).
const REWRITES: &[Rewrite] = &[word(REWRITE_ALIAS), word(REWRITE_SUGAR)];

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, and
/// the names config gives it.
pub const STATEMENT: Statement = Statement {
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(crate::NAME, env!("CARGO_PKG_VERSION"), 16)
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
        let settings = input.field(|i| &i.settings).bytes();
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
pub use table::door;
