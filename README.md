<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-secret-c

First-party signed kind:secret plugin library, written in C from busbar_plugin.h alone: the c secret, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `secret` | `c` | `busbar-secret-c` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-secret-c/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-secret-c/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-secret-c` is a `kind: secret` busbar plugin written in C from busbar's generated header
(`busbar_plugin.h`) alone: no Rust, no busbar crate.

## Config

Configured under the `c` module name.

## Build

Against `busbar_plugin.h` from busbar at the commit in `.busbar-ref`
(`crates/busbar-contract/include/`):

```bash
cc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -I <busbar>/crates/busbar-contract/include -o libbusbar_secret_c.so secret-c/*.c
```

## Tests

CI (busbar's `plugin-ci.yml` at the pin, `plugin_lang: c`) builds the library as above, loads it
through busbar's plugin loader (`load_dropped`) and drives the `kind: secret` conformance script
over `secret-c/conformance.json`, with its RED arm (the sources rebuilt at another kind ABI are
refused). Locally, from a busbar checkout at the pin:

```bash
BUSBAR_DROPPED_LIB=$PWD/libbusbar_secret_c.so BUSBAR_DROPPED_SOURCES=$PWD/secret-c \
BUSBAR_DROPPED_SCRIPT=$PWD/secret-c/conformance.json \
  cargo test --manifest-path <busbar>/Cargo.toml --locked -p busbar-plugin-loader \
  --test dropped_conformance -- --ignored
```

## License

Apache-2.0. See [LICENSE](LICENSE).
