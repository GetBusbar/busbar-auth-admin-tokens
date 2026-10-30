<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-admin-tokens

First-party signed kind:auth plugin cdylib: the built-in admin-tokens admin-auth module (the single operator admin token, compared in constant time), packaged as a droppable busbar plugin.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `admin-tokens` | `busbar-auth-admin-tokens-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-admin-tokens` is a `kind: auth` busbar plugin.

## Config

Configured under the `admin-tokens` module name (an `admin_auth:` chain entry).

**Settings** are a JSON string holding the lower-case SHA-256 hex digest of the admin token (64 hex
characters; surrounding whitespace is ignored and upper-case is lower-cased). The raw token is
refused, so no configuration has to hold it, and so is the digest of an empty token. A refusal never
echoes the value. A `refresh` carrying a rotated digest replaces the one held (the new token is
accepted and the old one refused with no re-open); settings that are not a digest are logged and the
held digest stands.

```json
"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
```

**Carriers.** The token is read off either of two lines: `Authorization: Bearer <token>` (scheme
matched case-insensitively, token taken verbatim after the first space) or `X-Admin-Token: <token>`.
A line that is not header text (visible ASCII, space or tab), a Bearer with no token, or a blank
`X-Admin-Token` is read as absent and logged at info (never the value); another scheme is a silent
absence.

**Verdicts.** Both carriers are always compared (constant time, over SHA-256 digests of the
candidates), so a request presenting both is indistinguishable from one presenting either.
- A carrier matching the digest: identity `admin` (the operator credential, full admin scope).
- A credential presented and not matching, whatever its shape: `Reject`, terminal in the admin chain.
- No credential presented: `Pass` (the chain denies if every module passes).

**Strips.** Whatever the verdict, both the `authorization` and `x-admin-token` lines are named for
the transport to strip: they are this module's credential lines.

## Build

```bash
cargo build --release -p busbar-auth-admin-tokens-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
