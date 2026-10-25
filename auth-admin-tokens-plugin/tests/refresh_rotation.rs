// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A ROTATED ADMIN TOKEN IS PICKED UP BY `refresh`, WITHOUT A RE-OPEN** (CREDENTIAL-LOCKDOWN P1.5).
//!
//! The lifecycle's `refresh` carries the NEW settings blob (`RefreshIn::settings`). The door is
//! opened over one token's digest, then refreshed over ANOTHER token's digest on the same instance:
//! the new token identifies and the old one is refused. A refresh over the unchanged digest (the
//! admin cache flush) changes nothing, and a refresh over settings that are not a digest keeps the
//! digest the instance holds (a refresh cannot refuse, so it never drops the instance to
//! nothing). Both doors: the logic crate's linked `door::door`, and this crate's dropped-in cdylib.
//!
//! RED on the SDK's default `refresh` (a no-op): after the refresh the new token is refused and the
//! old one still identifies.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, NamedValue, RequestFacts, StripName, VerifyIn, POINT_HEAD,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, OutHead, Outcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
use busbar_contract::sha256_hex;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

const OLD: &str = "the-operator-token";
const NEW: &str = "the-rotated-operator-token";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags: 0,
    }
}

struct Quiet;

impl EnvelopeSink for Quiet {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, _: Diagnostic<'_>) {}
    fn dropped(&self, _: Dropped) {}
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("refresh-rotation"),
        max_inflight_cap: 64,
        sink: Arc::new(Quiet),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

fn linked(d: &Dispatcher) -> Plugin<Auth> {
    let row = LinkedRow::of(busbar_auth_admin_tokens::door::door).expect("the door states itself");
    load_linked::<Auth>(&row, bind(d)).expect("the linked door loads")
}

fn dropped(d: &Dispatcher) -> Plugin<Auth> {
    let path = busbar_plugin_loader::conformance::cdylib_of("busbar_auth_admin_tokens_plugin");
    let stated =
        rendering_of(busbar_auth_admin_tokens::door::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(d)).expect("the dropped door loads")
}

/// The settings document for `token`: its SHA-256 digest as a JSON string.
fn settings_of(token: &str) -> String {
    format!("\"{}\"", sha256_hex(token.as_bytes()))
}

fn open(p: &Plugin<Auth>, settings: &str) -> Outcome {
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    o.input.settings = blob(settings.as_bytes(), BLOB_JSON);
    p.call(life::OPEN, &mut o).outcome
}

fn refresh(p: &Plugin<Auth>, settings: &str, generation: u64) -> Outcome {
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out = out_head();
    f.input.generation = generation;
    f.input.settings = blob(settings.as_bytes(), BLOB_JSON);
    p.call(life::REFRESH, &mut f).outcome
}

/// One `verify` at `Head` with `token` as the Bearer: `outcome verdict`.
fn bearer(p: &Plugin<Auth>, token: &str) -> String {
    let line = format!("Bearer {token}");
    let lines = [NamedValue {
        name: s("authorization"),
        value: blob(line.as_bytes(), BLOB_OCTETS),
    }];
    let mut buf = vec![0u8; 256];
    let mut groups = vec![Span { offset: 0, len: 0 }; 4];
    let mut strips = vec![
        StripName {
            name: Span { offset: 0, len: 0 },
            place: 0,
            _reserved: 0,
        };
        8
    ];
    let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.lines = lines.as_ptr();
    f.input.lines_len = lines.len();
    f.input.point = POINT_HEAD;
    f.input.strip = strips.as_mut_ptr();
    f.input.strip_cap = strips.len() as u32;
    f.input.request = RequestFacts {
        method: s("GET"),
        authority: s("node.example"),
        canonical_path: s("/admin/v1/keys"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 0,
    };
    f.input.out_buf = IdentityBuf {
        buf: buf.as_mut_ptr(),
        buf_cap: buf.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let c = p.call(slot::VERIFY, &mut f);
    let verdict = match f.out.verdict {
        VERDICT_IDENTITY => "identity",
        VERDICT_REJECT => "reject",
        VERDICT_PASS => "pass",
        _ => "?",
    };
    format!("{:?} {verdict}", c.outcome)
}

/// The script, one line per call.
fn script(p: &Plugin<Auth>) -> Vec<String> {
    vec![
        format!("open {:?}", open(p, &settings_of(OLD))),
        format!("old {}", bearer(p, OLD)),
        format!("new {}", bearer(p, NEW)),
        // The admin cache flush: unchanged settings, nothing changes.
        format!("flush {:?}", refresh(p, &settings_of(OLD), 2)),
        format!("old after flush {}", bearer(p, OLD)),
        format!("new after flush {}", bearer(p, NEW)),
        // The rotation: the new digest, on the same instance.
        format!("rotate {:?}", refresh(p, &settings_of(NEW), 3)),
        format!("old after rotate {}", bearer(p, OLD)),
        format!("new after rotate {}", bearer(p, NEW)),
        // Settings that are not a digest: the instance keeps the digest it holds.
        format!("bad {:?}", refresh(p, "\"the-raw-token\"", 4)),
        format!("old after bad {}", bearer(p, OLD)),
        format!("new after bad {}", bearer(p, NEW)),
    ]
}

const EXPECTED: &[&str] = &[
    "open Ready",
    "old Ready identity",
    "new Ready reject",
    "flush Ready",
    "old after flush Ready identity",
    "new after flush Ready reject",
    "rotate Ready",
    "old after rotate Ready reject",
    "new after rotate Ready identity",
    "bad Ready",
    "old after bad Ready reject",
    "new after bad Ready identity",
];

#[test]
fn refresh_picks_up_a_rotated_digest_without_a_reopen() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(script(&linked(&d)), EXPECTED, "the linked door");
    assert_eq!(script(&dropped(&d)), EXPECTED, "the dropped door");
}
