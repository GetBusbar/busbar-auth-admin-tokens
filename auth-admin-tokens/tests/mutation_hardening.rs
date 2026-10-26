// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening tests for `busbar-auth-admin-tokens`.
//!
//! ## Fold operator: `bearer_match | header_match` must stay bitwise-OR, not XOR
//!
//! No existing test presented BOTH carriers matching the configured token at once, so the fold's
//! operator (bitwise-OR vs XOR) was unobserved: OR and XOR only disagree when both operands are 1.
//! This file closes that gap directly.
//!
//! ## Non-JWT-shaped-credential invariant
//!
//! This module does not parse JWTs at all (it hashes an opaque bearer/header string and
//! constant-time-compares the digest against the configured admin-token hash). The invariant that
//! applies: no malformed/adversarial candidate string — regardless of shape — may ever be
//! `identified (accepted) without its SHA-256 digest exactly matching the configured hash. The
//! tests below drive that with empty strings, random-looking bytes-as-string, JWT-shaped-but-wrong
//! strings, and other garbage, all of which must fall through to `Pass`/`Reject`, never `Identify`.
//!
//! ## A JWS-shaped mismatch REJECTS, as every 1.5.5 mismatch did
//!
//! A presented credential that does not match is `Reject`, terminal in the `admin_auth:` chain,
//! whatever its shape: 1.5.5 never passed a wrong token on to the next module.

use busbar_auth_admin_tokens::{authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID};
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::sha256_hex;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// Closes the surviving `|` → `^` mutant: when BOTH carriers match the configured token, OR and XOR
/// disagree (OR says 1, matched; XOR says 0, unmatched). Only a test presenting both-correct carriers
/// distinguishes them — a real deployment could present a Bearer AND an `X-Admin-Token` that are both
/// the (same) correct admin token, and that must still `Identify`, not silently fail.
#[test]
fn both_carriers_correct_still_identifies() {
    let h = hash("secret");
    match authenticate_admin_tokens(Some(&h), Some("secret"), Some("secret")) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("both carriers correct must Identify, got {other:?}"),
    }
}

/// A NON-JWT-shaped (indeed, any-shaped) credential that does not hash-match the configured token
/// must never be `Accept`ed/`identified. This module never inspects structure — it hashes and
/// compares — so the property to prove is: garbage in, `Pass` or `Reject` out, NEVER `Identify`,
/// across a battery of malformed/adversarial shapes on both carriers.
#[test]
fn non_matching_credentials_of_any_shape_never_identify() {
    let h = hash("the-real-admin-token");
    let bad_candidates = [
        "",                                 // empty string
        "\0\x01\x02\x7f-random-bytes-ish",  // control-byte garbage (as UTF-8-lossy text)
        "a.b",                              // JWT-like but missing a segment (2 parts, not 3)
        "a.b.c.d",                          // too many dot-separated parts
        "not-a-jwt-at-all-just-plain-text", // no dots at all
        "not base64!!! ####",               // garbage, not valid base64
        "eyJhbGciOiJub25lIn0..",            // JWT-shaped header but empty payload/sig segments
        "the-real-admin-token-but-longer",  // near-miss, wrong length
        "the-real-admin-toke",              // near-miss, truncated by one char
        "the-real-admin-tokfn",             // near-miss, single-byte diff, same length
    ];
    for cred in bad_candidates {
        // As the Bearer carrier alone.
        match authenticate_admin_tokens(Some(&h), Some(cred), None) {
            Verdict::Identity(_) => {
                panic!("non-matching bearer candidate {cred:?} must never Identify")
            }
            Verdict::Pass | Verdict::Reject => {}
        }
        // As the X-Admin-Token carrier alone.
        match authenticate_admin_tokens(Some(&h), None, Some(cred)) {
            Verdict::Identity(_) => {
                panic!("non-matching header candidate {cred:?} must never Identify")
            }
            Verdict::Pass | Verdict::Reject => {}
        }
        // As BOTH carriers simultaneously (the both-carrier fold under test).
        match authenticate_admin_tokens(Some(&h), Some(cred), Some(cred)) {
            Verdict::Identity(_) => {
                panic!("non-matching both-carrier candidate {cred:?} must never Identify")
            }
            Verdict::Pass | Verdict::Reject => {}
        }
    }
}

/// A wrong credential on one carrier `Reject`s the whole verdict whatever the OTHER carrier's
/// shape.
#[test]
fn mixed_carriers_non_jws_wrong_still_rejects() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("wrong"), Some("a.b.c")),
        Verdict::Reject,
        "a non-JWS-shaped wrong bearer must still Reject even with a JWS-shaped header"
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("a.b.c"), Some("wrong")),
        Verdict::Reject,
        "a non-JWS-shaped wrong header must still Reject even with a JWS-shaped bearer"
    );
}
