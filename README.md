<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
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

Configured under the `file` module name. A secret reference is `{ file: /run/secrets/x }`, the sugar for
`{ module: file, settings: { path: ... } }`; it resolves to the bytes of the regular file named by `path`, untouched (a trailing newline is part of the secret).

A reference names `path` and nothing else: a missing or blank `path` fails INVALID, and so does
any other setting, named in the refusal. A missing file fails NOT_FOUND, an unreadable one DENIED, a transient I/O failure UNAVAILABLE; an empty file, a directory and a device node or fifo fail INVALID. The bytes are read into wiped buffers. The source declares the disk need (`declares.json`), so the host resolves it only at config time. No refusal carries the secret.

The source takes no instance settings (`secrets.file.settings`): none or `{}` opens it, and any
setting is refused naming it, at `validate`, `open` and `refresh` alike.

## Build

```bash
cargo build --release -p busbar-secret-file-plugin --features dropped-in
```

`dropped-in` puts the `busbar_plugin_door` symbol in the cdylib; a build that links the logic
crate as a row carries no door symbol.

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
