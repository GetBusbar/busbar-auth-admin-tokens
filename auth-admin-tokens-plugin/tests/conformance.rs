// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE ADMIN-AUTH MODULE, BOTH DOORS, ONE PLUGIN** — the `admin-tokens` plugin's linked +
//! dropped-in conformance on the auth kind's memory ABI, run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, admitted by the
//! loader's `load_linked`) and DROPPED IN (this crate's built cdylib, exporting the same door as
//! `busbar_plugin_door`, admitted by `load_dropped` only when its Statement renders byte for byte as
//! the linked row's). Each is bound to a real dispatcher and driven over the same cases through the
//! auth table: `validate` and `open` over settings that are a digest and settings that are not,
//! `verify` over the accepted token on either carrier or both, a wrong opaque token, a token in
//! another scheme's grammar, none — the Bearer as the host's extracted credential and, for a host
//! that lends none, on its `authorization` line — and the refusal of the login ops. The two
//! transcripts must agree, and every verdict must equal what `authenticate_admin_tokens` answers for
//! the same carriers.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a stated rendering one
//! byte off the door's is refused; the dropped-in door opened over a ROTATED token's digest judges
//! differently. A missing cdylib PANICS: this test IS the dropped-in door's proof, and never skips.

use std::mem::zeroed;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_auth_admin_tokens::{
    authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID, ADMIN_TOKEN_HEADER, AUTHORIZATION_HEADER,
};
use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, IdentifyOut, IdentityBuf, NamedValue, VerifyIn,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Span, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::redacted::sha256_hex;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, Called, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

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

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_admin_tokens_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| {
            panic!("the busbar-auth-admin-tokens-plugin cdylib ({file}) is not built")
        })
}

fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_admin_tokens::door::door).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("admin-tokens"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn secret(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

fn abi(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The settings document for a digest: a JSON string.
fn settings(digest: &str) -> String {
    serde_json::json!(digest).to_string()
}

/// A call's answer as the transcript spells it: outcome, lease, and error text.
fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn validate(p: &Plugin<Auth>, settings: &str) -> String {
    let mut reason = vec![0_u8; 1024];
    let mut i: ValidateIn = z();
    i.head = in_head();
    i.settings = json(settings.as_bytes());
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut f = Frame::new(i, out_head());
    spelled(&p.call(lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Auth>, settings: &str) -> String {
    let mut reason = vec![0_u8; 1024];
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = json(settings.as_bytes());
    i.generation = 1;
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(lc::OPEN, &mut f))
}

/// How the host presents the Bearer.
#[derive(Clone, Copy, Debug)]
enum Bearer {
    /// As the extracted candidate credential.
    Credential,
    /// On the `authorization` carrier line, as `Bearer <token>`.
    Line,
}

/// One `verify` as the transcript spells it: outcome, verdict, and the identity's subject.
fn verify(p: &Plugin<Auth>, how: Bearer, bearer: Option<&str>, header: Option<&str>) -> String {
    let line = bearer.map(|b| format!("Bearer {b}"));
    let mut carriers: Vec<NamedValue> = Vec::new();
    if let (Bearer::Line, Some(line)) = (how, &line) {
        carriers.push(NamedValue {
            name: abi(AUTHORIZATION_HEADER),
            value: secret(line.as_bytes()),
        });
    }
    if let Some(h) = header {
        carriers.push(NamedValue {
            name: abi(ADMIN_TOKEN_HEADER),
            value: secret(h.as_bytes()),
        });
    }
    let mut bytes = vec![0_u8; 4096];
    let mut groups: Vec<Span> = vec![z(); 16];
    let mut i: VerifyIn = z();
    i.head = in_head();
    i.credential = match (how, bearer) {
        (Bearer::Credential, Some(b)) => secret(b.as_bytes()),
        _ => Blob::ABSENT,
    };
    i.carrier = carriers.as_ptr();
    i.carrier_len = carriers.len();
    i.request.method = abi("GET");
    i.request.authority = abi("node.example");
    i.request.canonical_path = abi("/admin/v1/keys");
    i.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let mut o: IdentifyOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::VERIFY, &mut f);
    let verdict = match f.out.verdict {
        VERDICT_IDENTITY => {
            let s = f.out.identity.subject;
            let subject = &bytes[s.offset as usize..(s.offset + s.len) as usize];
            format!("Identity({})", String::from_utf8_lossy(subject))
        }
        VERDICT_REJECT => "Reject".into(),
        VERDICT_PASS => "Pass".into(),
        other => format!("verdict {other}"),
    };
    format!("{} {verdict}", spelled(&c))
}

/// The linked function's verdict for the same carriers, spelled the way `verify` is.
fn expected(digest: &str, bearer: Option<&str>, header: Option<&str>) -> String {
    let verdict = match authenticate_admin_tokens(Some(digest), bearer, header) {
        Verdict::Identity(id) => format!("Identity({})", id.subject),
        Verdict::Reject => "Reject".into(),
        Verdict::Pass => "Pass".into(),
    };
    format!("Ready lease=false  {verdict}")
}

/// The login ops a verify-only plugin refuses.
fn begin_login(p: &Plugin<Auth>) -> String {
    let mut i: BeginLoginIn = z();
    i.head = in_head();
    let mut o: BeginLoginOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(slot::BEGIN_LOGIN, &mut f))
}

/// What one door does, as one comparable transcript: its name, its refusal of settings that are not
/// a digest (and of the digest of an empty token) — judged by `open`, each on a fresh instance, as
/// `validate` leaves the settings to it — then, on an instance opened over `digest`, `verify` for
/// every case both ways, and the refused login op.
fn transcript(load: &dyn Fn() -> Plugin<Auth>, digest: &str) -> Vec<String> {
    let p = load();
    let mut t = vec![
        format!("name={}", p.name()),
        validate(&p, &settings(digest)),
        open(&load(), "\"the-raw-token\""),
        open(&load(), "{ not json"),
        open(&load(), &settings(&sha256_hex(b""))),
        open(&p, &settings(digest)),
    ];
    for how in [Bearer::Credential, Bearer::Line] {
        for (bearer, header) in CASES {
            t.push(verify(&p, how, bearer, header));
        }
    }
    t.push(begin_login(&p));
    t
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    })
}

/// The plugin admits and judges as ONE plugin through either way in, every verdict is the linked
/// function's, and the RED arms show none of it is vacuous.
#[test]
fn the_linked_and_the_dropped_in_admin_tokens_plugin_are_one_plugin() {
    let d = dispatcher();
    let digest = sha256_hex(TOKEN.as_bytes());
    let stated = row().statement;
    let linked =
        || -> Plugin<Auth> { load_linked(&row(), bind(&d)).expect("the linked door loads") };
    let dropped = || -> Plugin<Auth> {
        load_dropped(&cdylib(), &stated, bind(&d)).expect("the dropped-in door loads")
    };

    let a = transcript(&linked, &digest);
    let b = transcript(&dropped, &digest);
    assert_eq!(a, b, "the two doors are not one plugin");

    // Not a vacuous pass: the plugin answered what it must.
    let text = a.join("\n");
    assert_eq!(a[0], "name=admin-tokens", "{text}");
    assert!(a[1].starts_with("Ready"), "{text}");
    assert!(
        a[2].starts_with("Failed") && a[2].contains("SHA-256 digest"),
        "{text}"
    );
    assert!(!a[2].contains("the-raw-token"), "never echoed: {text}");
    assert!(a[3].starts_with("Failed"), "{text}");
    assert!(
        a[4].starts_with("Failed") && a[4].contains("empty token"),
        "{text}"
    );
    assert!(a[5].starts_with("Ready"), "{text}");
    for (n, (bearer, header)) in CASES.iter().chain(CASES.iter()).enumerate() {
        assert_eq!(
            a[6 + n],
            expected(&digest, *bearer, *header),
            "case {n}: {bearer:?} {header:?}"
        );
    }
    let verdicts = a[6..6 + 2 * CASES.len()].join("\n");
    for v in [
        format!("Identity({ADMIN_TOKENS_PRINCIPAL_ID})"),
        "Reject".into(),
        "Pass".into(),
    ] {
        assert!(verdicts.contains(&v), "no {v} among {verdicts}");
    }
    assert!(
        a.last().expect("a transcript").starts_with("Refused"),
        "{text}"
    );

    // RED ARM 1: the door asked for as another kind is refused, through either way in.
    assert!(load_linked::<Secret>(&row(), bind(&d)).is_err());
    assert!(load_dropped::<Secret>(&cdylib(), &stated, bind(&d)).is_err());

    // RED ARM 2: a stated rendering one byte off the door's is refused before any slot is called.
    let mut other = stated.clone();
    *other.last_mut().expect("a rendering has bytes") ^= 1;
    match load_dropped::<Auth>(&cdylib(), &other, bind(&d)) {
        Ok(_) => panic!("a Statement that is not the door's must be refused"),
        Err(e) => assert!(!e.to_string().is_empty()),
    }

    // RED ARM 3: the dropped-in door opened over a ROTATED digest judges differently.
    let rotated = transcript(&dropped, &sha256_hex(b"a-rotated-token"));
    assert_ne!(
        rotated, a,
        "a door judging another token must not compare equal"
    );
    assert!(!rotated[6..6 + 2 * CASES.len()]
        .join("\n")
        .contains("Identity"));
}
