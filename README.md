<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-secret-file

First-party signed kind:secret plugin cdylib: the file secret source (`{ file: /path }`), packaged as a droppable busbar plugin. busbar links it in the default build; a build without it resolves `{ file: /path }` only when the signed tarball is dropped into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `secret` | `file` | `busbar-secret-file-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-secret-file/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-secret-file/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-secret-file` is a `kind: secret` busbar plugin.

## Config

Configured under the `file` module name.

## Build

```bash
cargo build --release -p busbar-secret-file-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
