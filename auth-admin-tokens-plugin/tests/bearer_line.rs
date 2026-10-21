// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE BEARER ON ITS LINE** — the behavioural RED arm for "admin-tokens reads the Bearer off the
//! authorization line". Under busbar's auth points the host lends the request's field lines and no
//! credential of its own, so a module that read `request.credential()` never saw a Bearer: a
//! Bearer-only admin request passed instead of identifying, and a wrong Bearer passed instead of
//! being refused.
//!
//! This file names only what the logic crate exported before that change (its door, the fold, the
//! header carrier, the principal id) and spells the `authorization` line itself, so it COMPILES
//! against the old `auth-admin-tokens/src/lib.rs` and FAILS there on its assertions. On the change it
//! passes: the linked door, opened over the token's digest through the loader's auth rows on a real
//! dispatcher, identifies a Bearer on the `authorization` line (any scheme case), refuses a wrong
//! one, and names both credential lines for the transport to strip — on the spot and awaited alike.
//!
//! What a busbar host answers for a verifier that is overloaded or answers no verdict (503
//! `unavailable`, never a bad credential's 401) is the host's mapping, not this plugin's: the
//! plugin verifies on the spot, and the overloaded verdict is the host's gate before any crossing.
//! It is pinned busbar-side.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::sha256_hex;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{Budgets, DispatchConfig, Dispatcher};
use busbar_plugin_loader::sign::Manifest;
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The operator's token; the plugin is opened over its SHA-256 digest.
const TOKEN: &str = "the-operator-token";

/// The line a Bearer arrives on, spelled here so this file names nothing the change added.
const AUTHORIZATION: &str = "authorization";
const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// The fold the door must agree with, written out beside the transcript (the logic crate's only
/// public item is its door): no credential presented passes; a presented credential whose SHA-256
/// is the configured digest identifies the operator; any other presented credential rejects.
enum Fold {
    Identity,
    Reject,
    Pass,
}

/// The operator identity's subject.
const PRINCIPAL: &str = "admin";

fn fold(digest: &str, bearer: Option<&str>, header: Option<&str>) -> Fold {
    if bearer.is_none() && header.is_none() {
        return Fold::Pass;
    }
    if [bearer, header]
        .into_iter()
        .flatten()
        .any(|c| sha256_hex(c.as_bytes()) == digest)
    {
        Fold::Identity
    } else {
        Fold::Reject
    }
}

/// The linked door's statement: a first-party `kind: auth` plugin on the auth kind's memory ABI.
fn statement() -> Manifest {
    Manifest {
        name: "busbar-auth-admin-tokens".into(),
        alias: "admin-tokens".into(),
        kind: "auth".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: busbar_contract::abi::auth::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        // A linked row states its Statement through its door; the manifest carries none.
        statement: None,
        former_names: Vec::new(),
    }
}

/// The linked door, opened over the token's digest through the loader's auth rows.
fn opened() -> Arc<dyn AuthCalls> {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            statement(),
            busbar_auth_admin_tokens::door,
        )])
        .expect("the linked door admits the plugin");
    let dispatcher = Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..Default::default()
    });
    // Lent a seal as the composition root lends the kernel's: a verify reveals the lines it lends.
    assert!(dispatcher.lend_seal(busbar_contract::plugin::TestKernelSeal));
    let dispatcher = Arc::new(dispatcher);
    let digest = sha256_hex(TOKEN.as_bytes());
    AuthRows::new(Arc::new(registry), dispatcher)
        .open("admin-tokens", "admin-tokens", &serde_json::json!(digest))
        .expect("the plugin opens over a digest")
}

/// A request at the Head point carrying `lines` as presented.
fn request(lines: &[(&str, &str)]) -> VerifyRequest {
    VerifyRequest {
        point: AuthPoint::Head,
        lines: lines
            .iter()
            .map(|(n, v)| ((*n).to_string(), v.as_bytes().to_vec().into()))
            .collect(),
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

/// An answer as `verdict [strips]`.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let mut strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    strips.sort_unstable();
    format!("{verdict} [{}]", strips.join(", "))
}

/// The Bearer is read off the `authorization` line: alone it identifies (in any scheme case), a
/// wrong one is refused, and every answer names both credential lines for the transport to strip —
/// on the spot and awaited. RED on the old door: it read no Bearer, so the first three cases read
/// `Pass [x-admin-token]`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bearer_on_the_authorization_line_is_judged() {
    let door = opened();
    let operator = format!("Identity({PRINCIPAL})");
    let both = format!("[{AUTHORIZATION}, {ADMIN_TOKEN_HEADER}]");
    let bearer = format!("Bearer {TOKEN}");
    let cased = format!("bEaReR {TOKEN}");
    let cases = [
        (
            vec![(AUTHORIZATION, bearer.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, cased.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Bearer not-the-token")],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Basic not-a-bearer")],
            format!("Pass {both}"),
        ),
        (
            vec![(ADMIN_TOKEN_HEADER, TOKEN)],
            format!("{operator} {both}"),
        ),
    ];
    for (lines, want) in cases {
        let now = door
            .verify_now(&request(&lines))
            .expect("admin-tokens answers on the spot");
        assert_eq!(spelled(&now), want, "on the spot: {lines:?}");
        let awaited = Box::into_pin(door.verify(request(&lines))).await;
        assert_eq!(spelled(&awaited), want, "awaited: {lines:?}");
    }
}

/// The door's verdict for a Bearer on its line is the fold's own for that Bearer: the module's
/// both-carriers fold judges what the line carries, nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_door_judges_the_line_as_the_fold_judges_the_bearer() {
    let door = opened();
    let digest = sha256_hex(TOKEN.as_bytes());
    for token in [TOKEN, "not-the-token", "aaa.bbb.ccc"] {
        let line = format!("Bearer {token}");
        let got = door
            .verify_now(&request(&[(AUTHORIZATION, line.as_str())]))
            .expect("admin-tokens answers on the spot");
        let want = match fold(&digest, Some(token), None) {
            Fold::Identity => format!("Identity({PRINCIPAL})"),
            Fold::Reject => "Reject".into(),
            Fold::Pass => "Pass".into(),
        };
        assert!(
            spelled(&got).starts_with(&format!("{want} ")),
            "{token}: {} is not the fold's {want}",
            spelled(&got)
        );
    }
}
