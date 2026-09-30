// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE ADMIN-AUTH MODULE, BOTH DOORS, ONE ROW** — the `admin-tokens` plugin's linked + dropped-in
//! conformance on the auth kind's memory ABI, run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, registered through
//! the loader's `PluginRegistry::link`) and DROPPED IN (this crate's built cdylib, exporting the same
//! door as `busbar_plugin_door`, signed first-party under the SAME statement into a temp `plugins/`
//! directory and found by the loader's scan). Each arm is opened by the loader's auth rows on a real
//! dispatcher and driven over the same carrier cases — the accepted token on either carrier or both,
//! a wrong opaque token, a token in another scheme's grammar, none — each ON THE SPOT (ticket-less)
//! and SUBMITTED (awaited), plus its refusal of settings that are not a digest. The host lends the
//! request's field lines at the Head point, the Bearer as its `authorization` line. The two
//! transcripts must agree; every verdict must equal what `authenticate_admin_tokens` answers for the
//! same carriers, and every answer names both credential lines for the transport to strip, whatever
//! its verdict.
//!
//! The RED arms are in the same file: the same cdylib dropped in under a THIRD-PARTY signature is a
//! different row, and the dropped-in door opened over a ROTATED token's digest judges differently —
//! so the equality is not vacuous in either the row or the verdicts.

use std::sync::Arc;
use std::time::Duration;

use busbar_auth_admin_tokens::{
    authenticate_admin_tokens, ADMIN_TOKEN_HEADER, AUTHORIZATION_HEADER,
};
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::auth_calls::{Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::redacted::{sha256_hex, Redacted};
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{Budgets, DispatchConfig, Dispatcher};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the first-party dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[31u8; 32])
}

/// The version both arms state.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The operator's token. The plugin is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// The carriers each door judges, as (Bearer, `X-Admin-Token`): the accepted token on either and
/// on both, the token beside a wrong one, a wrong opaque token, a JWS-shaped token (another
/// scheme's grammar), a JWS beside a wrong opaque token, none.
const CASES: [(Option<&str>, Option<&str>); 9] = [
    (Some(TOKEN), None),
    (None, Some(TOKEN)),
    (Some(TOKEN), Some(TOKEN)),
    (Some("not-the-token"), Some(TOKEN)),
    (Some("not-the-token"), None),
    (None, Some("not-the-token")),
    (Some("aaa.bbb.ccc"), None),
    (Some("aaa.bbb.ccc"), Some("not-the-token")),
    (None, None),
];

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_admin_tokens_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| {
            panic!("the busbar-auth-admin-tokens-plugin cdylib ({file}) is not built")
        });
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both doors make: a first-party `kind: auth` plugin on the auth kind's memory ABI.
fn statement() -> Manifest {
    Manifest {
        name: "busbar-auth-admin-tokens".into(),
        alias: "admin-tokens".into(),
        kind: "auth".into(),
        version: VERSION.into(),
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
    }
}

/// THE LINKED DOOR: the logic crate's `door::door` through `PluginRegistry::link`.
fn linked() -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            statement(),
            busbar_auth_admin_tokens::door::door,
        )])
        .expect("the linked door admits the plugin")
}

/// THE DROPPED-IN DOOR: `lib` signed by `signer` into a fresh `plugins/` directory, scanned under a
/// policy holding the release key; any other signer is allowlisted as the manifest's publisher
/// (trusted, not first-party).
fn dropped(tag: &str, lib: &[u8], signer: &SigningKey) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!(
        "auth-admin-tokens-conf-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let third_party = signer.verifying_key() != release().verifying_key();
    let mut manifest = statement();
    if third_party {
        // A third party signs under its OWN publisher name: the first-party name is the release
        // key's alone.
        manifest.publisher = "a-third-party".into();
    }
    let publisher = (manifest.publisher.clone(), signer.verifying_key());
    let signed = sign(signer, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: std::iter::once(publisher).filter(|_| third_party).collect(),
        allow_unsigned: false,
        allow_third_party: third_party,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed plugin scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// The process's dispatcher, as the composition root builds one.
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

/// One carrier case as the host hands it to `verify` at the Head point: the Bearer on the
/// `authorization` line, the token on the `x-admin-token` line.
fn request(bearer: Option<&str>, header: Option<&str>) -> VerifyRequest {
    let line = |name: &str, value: String| (name.to_string(), Redacted::new(value.into_bytes()));
    let lines = bearer
        .map(|b| line(AUTHORIZATION_HEADER, format!("Bearer {b}")))
        .into_iter()
        .chain(header.map(|h| line(ADMIN_TOKEN_HEADER, h.to_string())))
        .collect();
    VerifyRequest {
        point: AuthPoint::Head,
        lines,
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

/// The lines every answer names for the transport to strip, as the transcript spells them.
const STRIPS: &str = "[authorization, x-admin-token]";

/// An answer as the transcript spells it: the verdict, the decision, the lines to strip.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    format!("{verdict} {:?} [{}]", a.decision, strips.join(", "))
}

/// The linked function's verdict, spelled the same way: an identity or a pass continues, a reject
/// stops, and both credential lines are named whatever the verdict.
fn expected(digest: &str, bearer: Option<&str>, header: Option<&str>) -> String {
    let verdict = match authenticate_admin_tokens(Some(digest), bearer, header) {
        Verdict::Identity(id) => format!("Identity({}) Continue", id.subject),
        Verdict::Reject => "Reject Stop".into(),
        Verdict::Pass => "Pass Continue".into(),
    };
    format!("{verdict} {STRIPS}")
}

/// What one door does, as one comparable transcript: the row's statement (every manifest field but
/// the two describing a tarball), whether it is first-party, the opened instance's name and facts, its verdict for every case on the spot and submitted, and its refusal of settings
/// that are not a digest.
async fn transcript(registry: PluginRegistry, digest: &str) -> serde_json::Value {
    let registry = Arc::new(registry);
    let p = registry
        .resolve("admin-tokens")
        .expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let rows = AuthRows::new(registry.clone(), dispatcher());
    let opened = rows
        .open("admin-tokens", "admin-tokens", &serde_json::json!(digest))
        .expect("the plugin opens over a digest");
    let mut now = Vec::new();
    let mut submitted = Vec::new();
    for (bearer, header) in CASES {
        let v = opened
            .verify_now(&request(bearer, header))
            .expect("admin-tokens answers on the spot");
        now.push(spelled(&v));
        let v = Box::into_pin(opened.verify(request(bearer, header))).await;
        submitted.push(spelled(&v));
    }
    let refused = rows
        .open(
            "admin-tokens",
            "admin-tokens",
            &serde_json::json!("the-raw-token"),
        )
        .err();
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "name": opened.name(),
        "facts": opened.facts(),
        "now": now,
        "submitted": submitted,
        "refused": refused,
    })
}

/// The plugin registers ONE row and judges as ONE plugin through either door, on the spot and
/// submitted, and every verdict is the linked function's — and the same cdylib under a third-party
/// signature, or opened over a rotated digest, does not compare equal (the RED arms).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_linked_and_the_dropped_in_admin_tokens_plugin_are_one_plugin() {
    let digest = sha256_hex(TOKEN.as_bytes());
    let lib = cdylib();

    let linked = transcript(linked(), &digest).await;
    let dropped_in = transcript(dropped("first-party", &lib, &release()), &digest).await;
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    let want: Vec<String> = CASES
        .iter()
        .map(|(b, h)| expected(&digest, *b, *h))
        .collect();
    assert_eq!(linked["now"], serde_json::json!(want));
    assert_eq!(linked["submitted"], serde_json::json!(want));
    let verdicts = linked["now"].to_string();
    for verdict in ["Identity(admin)", "Reject", "Pass"] {
        assert!(verdicts.contains(verdict), "no {verdict} among {verdicts}");
    }
    assert_eq!(linked["name"], "admin-tokens");
    assert_eq!(linked["facts"], 0, "a rotatable compare is never cached");
    assert!(
        linked["refused"].is_string(),
        "a raw token is refused as settings: {}",
        linked["refused"]
    );
    assert!(
        !linked["refused"].to_string().contains("the-raw-token"),
        "the refusal never echoes the settings"
    );

    // RED arm 1: the same cdylib under a third-party signature is a different row.
    let third = SigningKey::from_bytes(&[7u8; 32]);
    let foreign = transcript(dropped("third-party", &lib, &third), &digest).await;
    assert_ne!(
        foreign, linked,
        "a third-party row must not read as the first-party one"
    );
    assert_eq!(foreign["first_party"], false);

    // RED arm 2: the dropped-in door over a ROTATED digest judges differently.
    let rotated = transcript(
        dropped("rotated", &lib, &release()),
        &sha256_hex(b"a-rotated-token"),
    )
    .await;
    assert_eq!(rotated["row"], linked["row"], "one row either way");
    assert_ne!(
        rotated["now"], linked["now"],
        "a door judging another token must not compare equal"
    );
    assert!(!rotated["now"].to_string().contains("Identity"));
}
