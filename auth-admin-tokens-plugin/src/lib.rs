// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `admin-tokens` admin-auth module as a droppable `kind: auth` plugin: the logic crate
//! re-exported whole, and its door (`busbar_auth_admin_tokens::door::door`) exported as this image's
//! ONE symbol, `busbar_plugin_door` (`export_door!`, THE DESIGN §11.4). The logic crate holds no
//! `unsafe` and exports nothing, so a build that links it carries no door symbol.
#![deny(unsafe_code)]

pub use busbar_auth_admin_tokens::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is
/// the one exemption.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_admin_tokens::door::door);
}
