// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `admin-tokens` admin-auth module as a droppable `kind: auth` plugin: the logic crate's
//! one public item is its door (`busbar_auth_admin_tokens::door`), exported as this image's
//! ONE symbol, `busbar_plugin_door` (`export_door!`, THE DESIGN §11.4). This crate is the one busbar links, so it also
//! re-exports the door.
#![deny(unsafe_code)]

pub use busbar_auth_admin_tokens::door;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_admin_tokens::door);
}
