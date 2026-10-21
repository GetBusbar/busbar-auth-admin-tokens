// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-admin-tokens/src/lib.rs`.

use super::*;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

#[test]
fn no_configured_token_passes() {
    assert_eq!(
        authenticate_admin_tokens(None, Some("x"), None),
        Verdict::Pass
    );
}

#[test]
fn no_credential_passes() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, None),
        Verdict::Pass
    );
}

#[test]
fn either_carrier_identifies() {
    let h = hash("secret");
    for (b, hd) in [
        (Some("secret"), None),
        (None, Some("secret")),
        (Some("secret"), Some("wrong")),
        (Some("wrong"), Some("secret")),
    ] {
        match authenticate_admin_tokens(Some(&h), b, hd) {
            Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

/// A configured token that is itself JWS-shaped identifies.
#[test]
fn a_jws_shaped_configured_token_identifies() {
    let token = "abc.def.ghi";
    let h = hash(token);
    match authenticate_admin_tokens(Some(&h), Some(token), None) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identity, got {other:?}"),
    }
    let settings = format!("\"{h}\"");
    let plugin =
        <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[]).expect("a digest opens");
    match authenticate_admin_tokens(Some(&plugin.configured_hash), Some(token), None) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identity, got {other:?}"),
    }
}

#[test]
fn wrong_credential_rejects() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("nope"), None),
        Verdict::Reject
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, Some("nope")),
        Verdict::Reject
    );
}

// ── 1.5.5's CHAIN RULE ────────────────────────────────────────────────────────────────────
//
// `Reject` is TERMINAL in the admin chain, and 1.5.5 ended every presented mismatch in it,
// whatever the candidate's shape (`v155_verdicts.rs` holds the JWS-shaped cases).

#[test]
fn a_non_jws_wrong_credential_still_terminally_rejects() {
    let h = hash("secret");
    // Shapes that are NOT a compact JWS: no dots, too few segments, too many, and an empty
    // segment. Each is a genuine wrong-credential attempt against THIS module's grammar, and the
    // door stays shut on it.
    for candidate in ["nope", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b."] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(candidate), None),
            Verdict::Reject,
            "`{candidate}` is addressed to this module and wrong; it must deny, not pass"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(candidate)),
            Verdict::Reject,
            "`{candidate}` on the header carrier must deny too"
        );
    }
}

#[test]
fn a_jws_shaped_wrong_token_never_admits_and_the_fold_still_finds_the_token() {
    let h = hash("secret");
    let jws = "aaa.bbb.ccc";
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some(jws), None),
        Verdict::Reject
    );
    // The real token is still recognised on either carrier even when the OTHER carries a JWS.
    for (b, hd) in [(Some("secret"), Some(jws)), (Some(jws), Some("secret"))] {
        match authenticate_admin_tokens(Some(&h), b, hd) {
            Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

/// The `X-Admin-Token` line as 1.5.5 read it: blank or not header text is absent.
#[test]
fn a_blank_or_non_text_admin_header_is_absent() {
    for value in [
        &b""[..],
        "t\u{f6}k\u{e9}n".as_bytes(),
        b"tok\x01en",
        b"\xff",
    ] {
        assert_eq!(header_token(value), None, "{value:?}");
    }
    assert_eq!(header_token(b"the-token"), Some("the-token"));
    assert_eq!(header_token(b"a b\tc"), Some("a b\tc"));
}

// ── THE PLUGIN (`VerifyPlugin::open`) ───────────────────────────────────────────────────────

/// `open` takes the digest, never the raw token, and refuses anything that is not one — with a
/// message that does not echo what it was given.
#[test]
fn open_refuses_settings_that_are_not_a_sha256_hex_digest() {
    let h = hash("secret");
    for settings in [
        "".to_string(),
        "\"\"".to_string(),
        "\"   \"".to_string(),
        "\"secret\"".to_string(),
        format!("\"{}\"", &h[..63]),
        format!("\"{h}0\""),
        format!("\"{}\"", "zz".repeat(32)),
        // The digest, but not as the JSON string the settings document is.
        h.clone(),
        format!("{{\"token\":\"{h}\"}}"),
    ] {
        let err = <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[])
            .err()
            .unwrap_or_else(|| panic!("{settings:?} opened"));
        assert_eq!(err, NOT_A_DIGEST);
    }
}

/// The digest of the empty string is a blank admin token: refused, in either case, without echo.
#[test]
fn open_refuses_the_digest_of_an_empty_token() {
    let d = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hash(""), d);
    for digest in [d.to_string(), d.to_ascii_uppercase(), format!(" {d}\\n")] {
        let settings = format!("\"{digest}\"");
        let err = <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[])
            .err()
            .unwrap_or_else(|| panic!("{settings:?} opened"));
        assert_eq!(err, EMPTY_TOKEN);
        assert!(err.contains("empty token"), "{err}");
        assert!(!err.to_ascii_lowercase().contains(d), "{err}");
    }
}

/// The digest opens with surrounding whitespace and in either case.
#[test]
fn open_takes_the_digest_trimmed_in_either_case() {
    let h = hash("secret");
    let settings = format!("\"  {}\\n\"", h.to_ascii_uppercase());
    let plugin = <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[]).expect("opens");
    assert_eq!(plugin.configured_hash, h);
}

/// The Statement names the module and its two credential lines.
#[test]
fn the_statement_names_the_module_and_the_header_carrier() {
    assert_eq!(STATEMENT.name.len(), ADMIN_TOKENS_MODULE_NAME.len());
    assert_eq!(
        STATEMENT.mark_words_len(),
        2,
        "its two carriers are Statement word marks"
    );
    assert_eq!(TAIL.caps, busbar_contract::abi::auth::CAP_INBOUND);
    assert_eq!(
        TAIL.facts,
        busbar_contract::abi::auth::FACT_OPERATOR,
        "the operator credential, and a rotatable compare is never cached"
    );
    assert_eq!(
        TAIL.operator_principal.len(),
        ADMIN_TOKENS_PRINCIPAL_ID.len()
    );
}

/// The Bearer comes off the `authorization` line by 1.5.5's rule: the scheme in any case, a
/// non-empty token; any other value presents no Bearer.
#[test]
fn the_bearer_is_read_off_the_authorization_line() {
    assert_eq!(bearer_token(b"Bearer abc123"), Some("abc123"));
    assert_eq!(bearer_token(b"bEaReR abc123"), Some("abc123"));
    assert_eq!(bearer_token(b"Basic abc123"), None);
    assert_eq!(bearer_token(b"Bearer "), None);
    assert_eq!(bearer_token(b"Bearer"), None);
    assert_eq!(bearer_token(b""), None);
    assert_eq!(
        bearer_token(b"Bearer \xff"),
        None,
        "a non-UTF-8 value is not a Bearer"
    );
}
