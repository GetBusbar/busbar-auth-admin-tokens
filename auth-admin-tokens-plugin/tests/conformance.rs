// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the `admin-tokens` module two ways through the one loader: LINKED (the
//! logic crate's `door::door`) and DROPPED IN (this crate's built cdylib), over the auth kind's
//! script with the inputs in `conformance.json` (the accepted token on either carrier, a wrong
//! token, another scheme's grammar, none; the digest settings `open` refuses; a rotated digest that
//! identifies no one); every step's crossings exactly at the script's pin, the two folds equal, and
//! the suite's RED arms kept. `plugin-ci.yml` runs it under `--release`.

busbar_plugin_loader::conformance_suite! {
    door: busbar_auth_admin_tokens::door::door,
    cdylib: "busbar_auth_admin_tokens_plugin",
    inputs: include_str!("conformance.json"),
}
