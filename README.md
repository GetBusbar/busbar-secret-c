<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-secret-c

First-party signed kind:secret plugin library, written in C from busbar_plugin.h alone: the c secret, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `secret` | `secret-c` | `busbar-secret-c` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-secret-c/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-secret-c/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-secret-c` is a `kind: secret` busbar plugin written in C from busbar's generated header
(`busbar_plugin.h`) alone: no Rust, no busbar crate, no libc header, no allocator. It is decision
#84's witness (BUSBAR-1.6.0.md): a third party builds a busbar plugin from the header alone, and
busbar loads it through the same dropped-in door as every Rust plugin.

It serves named secrets whose material is written in its own settings.

## Config

Configured under the `c` module name. The instance's settings name each secret and its material:

```json
{"values": {"db": "s3cr3t", "api": "k3y"}}
```

`values` is the only setting; any other is refused, and so is an empty value or one over 1 KiB,
at `validate`, `open` and `refresh` alike.

A secret reference's settings name one of them: `{"name": "db"}`. A name it does not hold fails
with NOT_FOUND; a reference that is not `{"name": "<non-empty string>"}`, or that names another
setting, fails with INVALID. A resolved material is decoded straight into the host's buffer
(flagged secret) under no lease, and the plugin keeps no copy of it; a material over that buffer
gets the short-buffer answer. At most one instance, whose ops hold one lock (a `refresh` never
races a `resolve`); at most 8 KiB of settings and 1 KiB of material per name.

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
  cargo run --manifest-path <busbar>/Cargo.toml --locked -p busbar-test-kit \
  --example dropped_conformance
```

The unit tests (`secret-c/tests/unit.c`, not part of the plugin) drive the door directly for
what the conformance script does not judge, under ThreadSanitizer:

```bash
cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=thread -g -DBUSBAR_SECRET_C_UNIT \
  -I <busbar>/crates/busbar-contract/include -o /tmp/secret-c-unit \
  secret-c/busbar_secret_c.c secret-c/tests/unit.c -lpthread && /tmp/secret-c-unit
```

## License

Apache-2.0. See [LICENSE](LICENSE).
