<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-secret-file

First-party signed kind:secret plugin cdylib: the file secret source (`{ file: /path }`), packaged as a droppable busbar plugin. busbar links it in the default build; a build without it resolves `{ file: /path }` only when the signed tarball is dropped into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `secret` | `file` | `busbar-secret-file-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-secret-file/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-secret-file/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-secret-file` is a `kind: secret` busbar plugin. It resolves a secret reference `{ file: PATH }`
to the bytes of the regular file at `PATH`, untouched.

It needs the disk, so the host resolves it at config time on its disk lane. It is linked in busbar's
default build and also ships as a droppable cdylib for builds without it.

## Config

Configured under the `file` module name. A secret reference is `{ file: /run/secrets/x }`, the sugar for
`{ module: file, settings: { path: ... } }`; it resolves to the bytes of the regular file named by `path`, untouched (a trailing newline is part of the secret).

A reference names `path` and nothing else: a missing or blank `path` fails INVALID, and so does
any other setting, named in the refusal (escaped, so a key carrying newlines or control characters still makes one well-formed line). A missing file fails NOT_FOUND, an unreadable one DENIED, a transient I/O failure UNAVAILABLE; an empty file, a directory (on every platform, including one the process may not open) and a device node or fifo (including one the process may not open; such a path is refused before it is opened) fail INVALID, and so does a file over 16 MiB (`HARD_MAX_BYTES`, not configurable), refused naming the path. The open follows symlinks (Kubernetes projects secrets as symlinks into a `..data/` directory). The bytes are read into wiped buffers. The source declares the disk need (`declares.json`), so the host resolves it only at config time. No refusal carries the secret.

The source takes no instance settings (`secrets.file.settings`): none or `{}` opens it, and any
setting is refused naming it, at `validate`, `open` and `refresh` alike.

Reference `check` validates the path and allowed settings without filesystem I/O. A well-formed
reference to a missing file passes this syntax check; `resolve` judges the file and its value.

## Differences from 1.5.5

busbar 1.5.5 resolved `file:` in core (`crates/busbar/src/config/secret.rs` `resolve_builtin`, a
plain `std::fs::read`). Valid references behave as they did there: a regular file resolves to its
bytes whole and untouched, a blank file resolves, an empty file is refused, a missing file and a
missing or blank `path` keep 1.5.5's texts. Only invalid references are answered differently:

- **A setting other than `path` is refused, naming it.** 1.5.5 read `settings.path` and ignored
  every other key, so a typo (`{ module: file, settings: { pth: ... } }`) or a key meant for
  another source passed silently. It is refused before the missing-path check.
- **A directory is refused as a directory.** 1.5.5 answered the OS error (`Is a directory`, or
  `Permission denied` for one the process may not open); the refusal now says the path names a
  directory, not a file, on every platform.
- **A device node or fifo is refused without being opened.** 1.5.5 opened and read it: a fifo
  blocked the config thread until a writer appeared, `/dev/zero` read without bound, `/dev/null`
  answered EMPTY, and opening a device ran its driver's open (and close) side effects. The path's
  type is now judged before the open, so none of that happens, and one the process may not open
  is refused for what it is rather than as `Permission denied`.
- **A file over 16 MiB is refused, naming the path.** 1.5.5 read any length into memory; the
  secret kind's answer bound (`HARD_MAX_BYTES`) caps it, and the read stops there.

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
