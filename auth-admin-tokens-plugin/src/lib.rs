// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `admin-tokens` admin-auth module as a droppable `kind: auth` plugin: the logic crate with its
//! `dropped-in` door on, re-exported whole (its `open`, `BUSBAR_COLD_ENTRY` and
//! `dispatch_compiled_in` included). The door is registered by the logic crate's
//! `export_auth_plugin!`; this crate never calls the macro again (two door registrations in one
//! image).
#![deny(unsafe_code)]

pub use busbar_auth_admin_tokens::*;
