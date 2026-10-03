// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `admin-tokens` ADMIN auth PLUGIN.
//!
//! A default-included, compile-removable module for the `admin_auth:` chain (the parallel chain
//! gating `/admin/v1/*`): the single operator admin token, presented as `Authorization: Bearer` or
//! `X-Admin-Token`. Architecturally a peer of any external admin module (AD/OIDC); this one is
//! credential-compare only. An admin credential legitimately arrives on two carriers, and the
//! constant-time both-carriers fold lives INSIDE the module: selecting a carrier before the compare
//! would reintroduce the timing observable the fold kills.
//!
//! ## One door, on the auth kind's memory ABI (THE DESIGN §11.4, §11.6)
//!
//! [`door::door`] is the plugin's `plugin_door!` door, built by the SDK's `auth_verify_door!` over
//! [`AdminTokens`]: a `kind: auth` plugin that states `CAP_INBOUND` only, reads its two credential
//! lines (`authorization` for the Bearer, and `x-admin-token`), and judges on the spot. A build that LINKS this crate
//! registers that door as its `admin-tokens` row; the dropped-in build
//! (`busbar-auth-admin-tokens-plugin`) exports the SAME door as `busbar_plugin_door`. Every verdict
//! either way is [`authenticate_admin_tokens`]'s.
//!
//! THE TEMPLATE for porting a `kind: auth` plugin onto the memory ABI: implement
//! `abi::sdk::auth_door::VerifyPlugin` (open from the settings document, verify over the
//! `VerifyView`), state the tail with `verify_tail`, and let `auth_verify_door!` write the door. The
//! crate holds no `unsafe`.

#![forbid(unsafe_code)]

use busbar_contract::abi::auth::AuthTail;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Verdict, VerifiedIdentity, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::redacted::{constant_time_eq, sha256_hex};

/// The fixed principal id the operator admin token identifies as. The built-in operator credential
/// carries FULL admin scope by definition (it is the root credential the deployment was born with);
/// group-mapped external principals get their scope from `group_map:` instead.
pub const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

/// The module name: the `admin_auth:` chain entry this module answers.
pub const ADMIN_TOKENS_MODULE_NAME: &str = "admin-tokens";

/// The second carrier the operator token may arrive on (lower-case); the first is the Bearer.
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// The line the Bearer arrives on (lower-case), as `Bearer <token>`.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The token of an `Authorization` value in the Bearer scheme: the scheme matched case-insensitively,
/// the token non-empty. Any other value (another scheme, non-UTF-8, no token) presents no Bearer.
#[must_use]
pub fn bearer_token(value: &[u8]) -> Option<&str> {
    let (scheme, token) = std::str::from_utf8(value).ok()?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// The operator identity.
fn operator() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: ADMIN_TOKENS_PRINCIPAL_ID.to_string(),
        ..VerifiedIdentity::default()
    }
}

/// Judge the presented admin credential carriers against the configured admin token hash
/// (SHA-256 hex, pre-computed by the host).
///
/// Timing stance: BOTH carrier comparisons run UNCONDITIONALLY and fold with bitwise-OR — a request
/// presenting both a Bearer and an `X-Admin-Token` never skips the second compare, so "Bearer
/// matched" and "Bearer missed, header matched" are indistinguishable. Both candidates are
/// SHA-256-hashed before the constant-time compare, so candidate length leaks nothing. A missing
/// carrier contributes 0.
///
/// `None` hash (no admin token configured) ⇒ `Pass` — this module has nothing to judge; a chain
/// that ends all-`Pass` is denied (fail-closed), preserving "admin API disabled without a token".
///
/// SHAPE PRE-CHECK — THE CHAIN HAS TO COMPOSE. A candidate shaped like a JWS/JWT compact
/// serialization (three non-empty dot-separated segments) is never this module's credential
/// grammar: admin-tokens compares an opaque token HASH, it does not parse structured tokens. Such a
/// candidate belongs to a different scheme — typically an OIDC/AD admin module configured later in
/// the same `admin_auth:` chain, which legitimately shares the `Authorization: Bearer` carrier.
/// `Reject` is TERMINAL in the admin chain, so rejecting it here would deny the request before that
/// arm ever ran.
///
/// Fail-closed but NON-TERMINAL: this module still never identifies such a candidate; what changes
/// is that a carrier which is absent, or present but JWS-shaped, does not count as "this module was
/// addressed", so a JWS-shaped mismatch alone DEFERS (`Pass`) and keeps the next arm reachable. A
/// carrier that is present and NOT JWS-shaped is a genuine wrong-credential attempt against this
/// module and still `Reject`s. The shape test reads only the PUBLIC candidate string and never the
/// compare result, and both constant-time hash compares still run unconditionally on every
/// presented carrier regardless of shape.
#[must_use]
pub fn authenticate_admin_tokens(
    configured_hash: Option<&str>,
    bearer: Option<&str>,
    header: Option<&str>,
) -> Verdict {
    let Some(configured_hash) = configured_hash else {
        return Verdict::Pass;
    };
    if bearer.is_none() && header.is_none() {
        // No credential presented for this module — defer (the chain's all-Pass denies).
        return Verdict::Pass;
    }
    // Read off the PUBLIC candidate strings only, BEFORE either compare, so no branch below can
    // depend on a compare result: the constant-time fold is untouched.
    let bearer_is_jws = bearer.is_some_and(is_jws_shaped);
    let header_is_jws = header.is_some_and(is_jws_shaped);
    let bearer_match = u8::from(
        bearer
            .map(|b| constant_time_eq(&sha256_hex(b.as_bytes()), configured_hash))
            .unwrap_or(false),
    );
    let header_match = u8::from(
        header
            .map(|h| constant_time_eq(&sha256_hex(h.as_bytes()), configured_hash))
            .unwrap_or(false),
    );
    if std::hint::black_box(bearer_match | header_match) != 0 {
        return Verdict::Identity(operator());
    }
    // Only a carrier that was actually presented AND is not JWS-shaped counts as "addressed to this
    // module, and wrong" — that still terminally denies. A carrier that is absent, or present but
    // carrying some other scheme's grammar, defers instead of short-circuiting the chain.
    let bearer_addressed_me = bearer.is_some() && !bearer_is_jws;
    let header_addressed_me = header.is_some() && !header_is_jws;
    if bearer_addressed_me || header_addressed_me {
        Verdict::Reject
    } else {
        Verdict::Pass
    }
}

/// Whether `candidate` is shaped like a JWS/JWT compact serialization: exactly three dot-separated
/// segments, none of them empty (`header.payload.signature`).
///
/// A pure SHAPE test — it says nothing about validity, signature or issuer, and is never used to
/// admit anything. Its only job is to recognise "this is not admin-tokens' grammar" so the chain
/// can carry the candidate on to the arm whose grammar it IS.
fn is_jws_shaped(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let (Some(a), Some(b), Some(c), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    !a.is_empty() && !b.is_empty() && !c.is_empty()
}

/// The refusal of settings that are not a digest. It never echoes what it was given.
pub const NOT_A_DIGEST: &str =
    "admin-tokens plugin config must be the admin token's SHA-256 digest \
                                as 64 hex characters (the value is not echoed)";

/// The refusal of the digest of an empty token: a blank admin token is refused, as the linked path
/// refuses it. It never echoes what it was given.
pub const EMPTY_TOKEN: &str =
    "admin-tokens plugin config is the SHA-256 digest of an empty token, \
                               which is refused (the value is not echoed)";

/// SHA-256 of the empty string: the digest of a blank admin token.
const EMPTY_TOKEN_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The configured digest out of the settings document: a JSON string holding the admin token's
/// SHA-256 digest as 64 hex characters (surrounding whitespace ignored), lower-cased. Fail-closed:
/// anything else is refused, and the raw token is never accepted, so no configuration has to hold
/// it.
///
/// # Errors
/// [`NOT_A_DIGEST`]; [`EMPTY_TOKEN`] for the digest of an empty token.
pub fn digest_of(settings: &[u8]) -> Result<String, &'static str> {
    let text: String = serde_json::from_slice(settings).map_err(|_| NOT_A_DIGEST)?;
    let digest = text.trim();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NOT_A_DIGEST);
    }
    let digest = digest.to_ascii_lowercase();
    if digest == EMPTY_TOKEN_SHA256 {
        return Err(EMPTY_TOKEN);
    }
    Ok(digest)
}

/// A carrier's value as the text the compare hashes; a non-UTF-8 value is not this module's
/// grammar and is judged as the wrong credential it is.
fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("\u{fffd}")
}

/// THE PLUGIN: the configured admin token's SHA-256 hex digest (never the raw token).
#[derive(Debug)]
pub struct AdminTokens {
    configured_hash: String,
}

impl VerifyPlugin for AdminTokens {
    fn open(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Self {
            configured_hash: digest_of(settings)?,
        })
    }

    /// The Bearer (off the `authorization` line) and the `X-Admin-Token` line are put to
    /// [`authenticate_admin_tokens`] in one call, so the fold is the module's own. The Bearer is
    /// the host's extracted candidate credential; a host that lends none presents the Bearer on its
    /// `authorization` carrier line, which is read the same way.
    fn verify(&self, request: &VerifyView<'_>) -> Verdict {
        let bearer = request
            .credential()
            .map(text)
            .or_else(|| request.carrier(AUTHORIZATION_HEADER).and_then(bearer_token));
        authenticate_admin_tokens(
            Some(&self.configured_hash),
            bearer,
            request.carrier(ADMIN_TOKEN_HEADER).map(text),
        )
    }
}

/// The credential lines `verify` reads, the Statement's carrier word marks: the host lends exactly
/// these.
const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION_HEADER), carrier(ADMIN_TOKEN_HEADER)];

/// The auth tail: inbound only, judged on the spot, nothing cached (a compare against a value the
/// operator can rotate is never worth caching), reading its two credential lines (the Statement's
/// carrier word marks).
const TAIL: &AuthTail = &verify_tail(0);

/// What the plugin states: its name, version, the concurrency it serves and its two carriers.
pub const STATEMENT: Statement = with_tail(
    Statement {
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(ADMIN_TOKENS_MODULE_NAME, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

/// THE DOOR: `door::door`, the plugin's `DoorFn`. A build that links this crate registers it as the
/// `admin-tokens` row; `busbar-auth-admin-tokens-plugin` exports it as `busbar_plugin_door`.
pub mod door {
    busbar_contract::auth_verify_door!(super::AdminTokens, super::STATEMENT);
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
