// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE ADMIN-AUTH MODULE, BOTH DOORS, ONE ROW** — the `admin-tokens` module's linked + dropped-in
//! conformance, run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The module is held two ways at once: LINKED (this crate's `BUSBAR_COLD_ENTRY`, registered through
//! the loader's `PluginRegistry::link`) and DROPPED IN (this crate's built cdylib, signed first-party
//! under the SAME statement into a temp `plugins/` directory and found by the loader's scan). Each
//! arm is opened by the one `open_auth` and driven over the same token cases — the accepted token
//! (`Identify`), a wrong opaque token (`Reject`), a token in another scheme's grammar (`Pass`), and
//! no credential (`Pass`) — plus the module's name and cacheability and its refusal of a config that
//! is not a digest. The two transcripts must agree byte for byte, and each must equal what
//! `authenticate_admin_tokens` — the function busbar's admin chain calls when it links this crate —
//! answers for the same candidate on the Bearer carrier.
//!
//! The RED arms are in the same file: the same cdylib dropped in under a THIRD-PARTY signature is a
//! different row, and the dropped-in door opened over a ROTATED token's digest judges differently —
//! so the equality is not vacuous in either the row or the verdicts.
//!
//! Ported from busbar's `crates/plugin-loader/src/tests/auth_verify_conformance_tests.rs`, where the
//! module was proven both ways before it moved to this repo; busbar still runs that test against the
//! pinned module.
use busbar_auth_admin_tokens_plugin::authenticate_admin_tokens;
use busbar_contract::redacted::sha256_hex;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the first-party dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[31u8; 32])
}

/// The version both arms state.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The operator's token. The module is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// The candidates each door judges: the accepted token, a wrong opaque token, a JWS-shaped token
/// (another scheme's grammar), none.
const CANDIDATES: [Option<&str>; 4] = [
    Some(TOKEN),
    Some("not-the-token"),
    Some("aaa.bbb.ccc"),
    None,
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

/// The statement both doors make for the module: a first-party `kind: auth` plugin at the highest
/// auth payload schema the pinned loader supports.
fn statement() -> Manifest {
    let abi = busbar_plugin_loader::supported_abi("auth")
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: "busbar-auth-admin-tokens".into(),
        alias: "admin-tokens".into(),
        kind: "auth".into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
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

/// THE LINKED DOOR: this crate's `BUSBAR_COLD_ENTRY` through `PluginRegistry::link`.
fn linked() -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(
            statement(),
            &busbar_auth_admin_tokens_plugin::BUSBAR_COLD_ENTRY,
        )])
        .expect("the linked door admits the module")
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
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed module scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// What one door does, as one comparable transcript: the row's statement (every manifest field but
/// the two describing a tarball), whether it is first-party, the opened module's name and
/// cacheability, its verdict for every candidate, and its refusal of a config that is not a digest.
fn transcript(registry: &PluginRegistry, digest: &str) -> serde_json::Value {
    let p = registry
        .resolve("admin-tokens")
        .expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let module = registry
        .open_auth("admin-tokens", digest)
        .expect("the module opens over a digest");
    let verdicts: Vec<String> = CANDIDATES
        .iter()
        .map(|c| format!("{c:?} -> {:?}", module.authenticate(*c)))
        .collect();
    let refused = registry
        .open_auth("admin-tokens", "the-raw-token")
        .err()
        .map(|e| e.to_string());
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "name": module.name(),
        "cacheable": module.cacheable(),
        "verdicts": verdicts,
        "refused": refused,
    })
}

/// The module registers ONE row and judges as ONE module through either door, and every verdict is
/// the linked function's — and the same cdylib under a third-party signature, or opened over a
/// rotated digest, does not compare equal (the RED arms).
#[test]
fn the_linked_and_the_dropped_in_admin_tokens_module_are_one_module() {
    let digest = sha256_hex(TOKEN.as_bytes());
    let lib = cdylib();

    let linked = transcript(&linked(), &digest);
    let dropped_in = transcript(&dropped("first-party", &lib, &release()), &digest);
    assert_eq!(linked, dropped_in, "the two doors are not one module");

    // Every verdict is the linked function's, over the Bearer carrier — and the cases reach all
    // three, so the equality covers Identify, Reject and Pass alike.
    let expected: Vec<String> = CANDIDATES
        .iter()
        .map(|c| {
            format!(
                "{c:?} -> {:?}",
                authenticate_admin_tokens(Some(&digest), *c, None)
            )
        })
        .collect();
    assert_eq!(linked["verdicts"], serde_json::json!(expected));
    let verdicts = linked["verdicts"].to_string();
    for verdict in ["Identify", "Reject", "Pass"] {
        assert!(verdicts.contains(verdict), "no {verdict} among {verdicts}");
    }
    assert_eq!(linked["name"], "admin-tokens");
    assert_eq!(linked["cacheable"], false);
    assert!(
        linked["refused"].is_string(),
        "a raw token is refused as config: {}",
        linked["refused"]
    );

    // RED arm 1: the same cdylib under a third-party signature is a different row.
    let third = SigningKey::from_bytes(&[7u8; 32]);
    let foreign = transcript(&dropped("third-party", &lib, &third), &digest);
    assert_ne!(
        foreign, linked,
        "a third-party row must not read as the first-party one"
    );
    assert_eq!(foreign["first_party"], false);

    // RED arm 2: the dropped-in door over a ROTATED digest judges differently.
    let rotated = transcript(
        &dropped("rotated", &lib, &release()),
        &sha256_hex(b"a-rotated-token"),
    );
    assert_eq!(rotated["row"], linked["row"], "one row either way");
    assert_ne!(
        rotated["verdicts"], linked["verdicts"],
        "a door judging another token must not compare equal"
    );
    assert!(!rotated["verdicts"].to_string().contains("Identify"));
}
