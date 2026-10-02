<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-admin-tokens

First-party signed kind:auth plugin cdylib: the built-in admin-tokens admin-auth module (the single operator admin token, compared in constant time), packaged as a droppable busbar plugin.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `admin-tokens` | `busbar-auth-admin-tokens-plugin` | 1.6.0 (pinned in `.busbar-ref`) | MIT |

[![ci](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-admin-tokens` is a `kind: auth` busbar plugin.

## Config

Configured under the `admin-tokens` module name.

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
