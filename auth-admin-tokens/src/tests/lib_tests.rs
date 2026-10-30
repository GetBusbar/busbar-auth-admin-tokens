// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-admin-tokens/src/lib.rs`.

use super::*;
use busbar_contract::sha256_hex;

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
    match authenticate_admin_tokens(Some(&plugin.digest()), Some(token), None) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identity, got {other:?}"),
    };
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
    assert_eq!(*plugin.digest(), h);
}

/// The Statement names the module and its two credential lines.
#[test]
fn the_statement_names_the_module_and_the_header_carrier() {
    assert_eq!(STATEMENT.name.len, ADMIN_TOKENS_MODULE_NAME.len());
    assert_eq!(
        STATEMENT.mark_words_len, 2,
        "its two carriers are Statement word marks"
    );
    assert_eq!(TAIL.caps, busbar_contract::abi::auth::CAP_INBOUND);
    assert_eq!(
        TAIL.facts,
        busbar_contract::abi::auth::FACT_OPERATOR,
        "the operator credential, and a rotatable compare is never cached"
    );
    assert_eq!(TAIL.operator_principal.len, ADMIN_TOKENS_PRINCIPAL_ID.len());
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

/// 1.5.5's `extract_bearer_token` was `split_once(' ')` with the token kept as-is: the split is on
/// the FIRST single space, the token is the rest verbatim (never trimmed), and only a space
/// separates scheme from token.
#[test]
fn the_bearer_split_is_the_first_single_space_and_the_token_is_verbatim() {
    assert_eq!(
        bearer_token(b"Bearer  secret"),
        Some(" secret"),
        "the token keeps its leading space"
    );
    assert_eq!(bearer_token(b"Bearer a b"), Some("a b"));
    assert_eq!(
        bearer_token(b"Bearer\tsecret"),
        None,
        "a tab is not the separator"
    );
    assert_eq!(
        bearer_token(b" Bearer secret"),
        None,
        "a leading space makes the scheme empty"
    );
    let h = hash("secret");
    assert!(
        matches!(
            authenticate_admin_tokens(Some(&h), bearer_token(b"Bearer  secret"), None),
            Verdict::Reject
        ),
        "the untrimmed token is a different credential: it is rejected"
    );
}

/// `Debug` never prints the admin token's digest.
#[test]
fn debug_never_prints_the_configured_digest() {
    let h = hash("secret");
    let settings = format!("\"{h}\"");
    let plugin = <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[]).expect("opens");
    let shown = format!("{plugin:?}");
    assert!(!shown.contains(&h), "{shown}");
    assert!(!shown.contains(&h[..16]), "{shown}");
}

/// A wrong token is refused AND the refusal is logged (module = admin-tokens), with neither the
/// presented token nor the configured digest in the line.
#[test]
fn a_wrong_token_reject_is_logged_without_the_token() {
    let h = hash("secret");
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    let verdict = tracing::subscriber::with_default(cap.clone(), || {
        authenticate_admin_tokens(Some(&h), Some("WRONG-TOKEN-TEXT"), None)
    });
    assert_eq!(verdict, Verdict::Reject);
    let logged = cap.messages().join("\n");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("mismatch"), "{logged:?}");
    assert!(!logged.contains("WRONG-TOKEN-TEXT"), "{logged:?}");
    assert!(!logged.contains(&h[..16]), "{logged:?}");
}

/// Passes (no token presented, none configured) are not refusals and log nothing.
#[test]
fn a_pass_logs_nothing() {
    let h = hash("secret");
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, None),
            Verdict::Pass
        );
    });
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// A credential line that is not header text is read as absent AND says so in the log, without the
/// bytes of the value.
#[test]
fn a_non_header_text_credential_line_is_logged() {
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert_eq!(bearer_line(b"Bearer sec\xffret"), None);
        assert_eq!(header_line(b"sec\x01ret"), None);
        // A well-formed non-Bearer scheme is a plain absence: no log.
        assert_eq!(bearer_line(b"Basic abc"), None);
    });
    let logged = cap.messages().join("\n");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("authorization"), "{logged:?}");
    assert!(logged.contains("x-admin-token"), "{logged:?}");
    assert!(!logged.contains("ret"), "value leaked: {logged:?}");
    assert_eq!(cap.messages().len(), 2, "{logged:?}");
}

/// A credential line that is PRESENT but yields no token (an empty Bearer token, a blank
/// `X-Admin-Token`) is read as absent AND says so once in the log, never the value. A non-Bearer
/// scheme stays a silent absence.
#[test]
fn a_present_line_with_no_token_is_logged() {
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert_eq!(bearer_line(b"Bearer "), None);
        assert_eq!(header_line(b""), None);
    });
    let logged = cap.messages().join("\n");
    assert!(logged.contains("authorization"), "{logged:?}");
    assert!(logged.contains("x-admin-token"), "{logged:?}");
    assert!(logged.contains("carries no token"), "{logged:?}");
    assert_eq!(cap.messages().len(), 2, "{logged:?}");

    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert_eq!(bearer_line(b"Basic abc"), None);
        assert_eq!(bearer_line(b"Bearer tok"), Some("tok"));
        assert_eq!(header_line(b"tok"), Some("tok"));
    });
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// The website claim "constant-time compare" is held structurally, never by timing (a timing test
/// is flaky): the module's own non-test source compares the candidate's digest with the configured
/// one through busbar-contract's `constant_time_eq` and through no other equality.
#[test]
fn the_token_comparison_goes_through_the_constant_time_primitive() {
    let source = include_str!("../lib.rs");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("the production half of lib.rs");
    let code: String = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("use busbar_contract::constant_time_eq;"),
        "the primitive must be busbar-contract's constant_time_eq"
    );
    assert_eq!(
        code.matches("constant_time_eq(").count(),
        1,
        "exactly one comparison site"
    );
    assert!(
        code.contains("constant_time_eq(&hex, configured_hash)"),
        "the candidate digest is compared with the configured digest through the primitive"
    );
    // No short-circuiting equality anywhere near the credential or its digest.
    for banned in [
        "== configured_hash",
        "configured_hash ==",
        "!= configured_hash",
        "configured_hash !=",
        "hex ==",
        "== hex",
        "token ==",
        "== token",
        "starts_with(",
        ".eq(",
        ".ne(",
        "assert_eq!(hex",
        "memcmp",
    ] {
        assert!(
            !code.contains(banned),
            "`{banned}` is a non-constant-time comparison in the token path"
        );
    }
    // The primitive itself still behaves as an equality over bytes.
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "abcd"));
}

/// An admin token never appears in a log line or an error string: not when it matches, not when it
/// does not, not on a malformed line, and not when the settings that should hold its digest hold
/// the raw token (a refusal that does not echo it).
#[test]
fn an_admin_token_never_appears_in_logs_or_errors() {
    const TOKEN: &str = "ADMIN-SENTINEL-7f3a91c2e8b4";
    let h = hash(TOKEN);
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    let mut surfaces: Vec<String> = Vec::new();
    tracing::subscriber::with_default(cap.clone(), || {
        // A match on each carrier, a mismatch on each carrier, a near miss.
        let _ = authenticate_admin_tokens(Some(&h), Some(TOKEN), None);
        let _ = authenticate_admin_tokens(Some(&h), None, Some(TOKEN));
        let _ = authenticate_admin_tokens(Some(&h), Some(&format!("{TOKEN}x")), None);
        let _ = authenticate_admin_tokens(Some(&h), None, Some(&format!("x{TOKEN}")));
        // Malformed lines carrying the token's bytes.
        let _ = bearer_line(format!("Bearer {TOKEN}\u{1}").as_bytes());
        let _ = header_line(format!("{TOKEN}\u{7f}").as_bytes());
        let _ = bearer_line(format!("Bearer {TOKEN}\u{ff}").as_bytes());
    });
    // The refusals of settings: the raw token, a quoted raw token, and the empty token's digest.
    for settings in [
        TOKEN.to_string(),
        format!("\"{TOKEN}\""),
        format!("\"{}\"", hash("")),
        format!("{{\"token\": \"{TOKEN}\"}}"),
    ] {
        match digest_of(settings.as_bytes()) {
            Err(e) => surfaces.push(e.to_string()),
            Ok(d) => panic!("settings {settings:?} were accepted as the digest {d:?}"),
        }
        match <AdminTokens as VerifyPlugin>::open(settings.as_bytes(), &[]) {
            Err(e) => surfaces.push(e.to_string()),
            Ok(_) => panic!("open accepted {settings:?}"),
        }
    }
    // The plugin's Debug, with a digest held.
    let plugin =
        <AdminTokens as VerifyPlugin>::open(format!("\"{h}\"").as_bytes(), &[]).expect("opens");
    surfaces.push(format!("{plugin:?}"));
    surfaces.extend(cap.messages());
    for surface in &surfaces {
        assert!(!surface.contains(TOKEN), "token leaked: {surface:?}");
        assert!(!surface.contains(&h), "digest leaked: {surface:?}");
        assert!(
            !surface.contains(&h[..16]),
            "digest prefix leaked: {surface:?}"
        );
    }
    assert!(!cap.messages().is_empty(), "the refusals were logged");
}

/// The Statement declares the stateless verifier's concurrency, as webhook-signature, sigv4 and oauth do.
#[test]
fn statement_concurrency_is_1024() {
    assert_eq!(STATEMENT.max_inflight, 1024);
}

/// A settings refusal is a line in the contract's instance-relative form (`settings: <reason>`), so
/// the host renders it under the instance (`auth.<name>.settings: ...`) and the validate rule holds.
#[test]
fn a_settings_refusal_is_an_instance_relative_settings_line() {
    use busbar_contract::abi::mechanism::lifecycle::{check_validate_refusal, refusal_lines};
    for refusal in [NOT_A_DIGEST, EMPTY_TOKEN] {
        assert!(refusal.starts_with("settings: "), "{refusal}");
        assert!(
            check_validate_refusal(refusal.as_bytes()).is_ok(),
            "{refusal}"
        );
        let lines = refusal_lines("auth", "admin-tokens", refusal);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("auth.admin-tokens.settings: "),
            "{lines:?}"
        );
        assert!(refusal.contains("not echoed"), "{refusal}");
    }
}

/// A refresh whose settings are not a digest keeps the digest held AND says so in the log once
/// (module = admin-tokens, a reason word), never echoing the settings it was given.
#[test]
fn a_refused_refresh_is_logged_and_keeps_the_digest() {
    const RAW: &str = "REFRESH-RAW-TOKEN-5c1e";
    let h = hash("secret");
    let plugin =
        <AdminTokens as VerifyPlugin>::open(format!("\"{h}\"").as_bytes(), &[]).expect("opens");
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert_eq!(plugin.refresh(format!("\"{RAW}\"").as_bytes(), &[]), 0);
    });
    assert_eq!(*plugin.digest(), h, "the held digest stands");
    let logged = cap.messages().join("\n");
    assert_eq!(cap.messages().len(), 1, "{logged:?}");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("refresh"), "{logged:?}");
    assert!(!logged.contains(RAW), "settings echoed: {logged:?}");
    // An accepted refresh is not a refusal: it logs nothing.
    let rotated = hash("rotated");
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        plugin.refresh(format!("\"{rotated}\"").as_bytes(), &[]);
    });
    assert_eq!(*plugin.digest(), rotated);
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// The presented token's digest and its hex are material derived from the secret: both live in
/// wiping holders, so neither outlives the compare in memory (read off the production source, as the
/// constant-time test reads it).
#[test]
fn the_presented_tokens_digest_is_wiped_after_the_compare() {
    let source = include_str!("../lib.rs");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("the production half of lib.rs");
    assert!(
        production.contains("let digest = Zeroizing::new(sha256(token.as_bytes()));"),
        "the candidate's raw digest is held wiped"
    );
    assert!(
        production.contains("let mut hex = Zeroizing::new([0u8; 64]);"),
        "the candidate's hex is held wiped"
    );
}
