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

Configured under the `secret-c` module name (the Statement states it as its own alias):
`{ module: secret-c, settings: { name: db } }` for a reference. The instance's settings name each
secret and its material:

```json
{"values": {"db": "s3cr3t", "api": "k3y"}}
```

`values` is the only setting, given once; any other is refused, and so is an empty value or one
over 1 KiB, and a name that is empty, over 1 KiB or given twice (every name kept can be asked for),
at `validate`, `open` and `refresh` alike. Settings of no bytes are refused
(`settings: c requires settings (values); none provided`). A refused `refresh` keeps the settings it replaced.

A secret reference's settings name one of them: `{"name": "db"}`. A name it does not hold fails
with NOT_FOUND (`c holds no secret by that name`); a reference that is not
`{"name": "<non-empty string>"}`, that names another setting, or that names `name` twice, fails
with INVALID, in the vault plugin's words ("missing or non-string `name` in secret reference
settings", `c secret reference names only settings.name (fail-closed)`, ...; the kernel prefixes the
module). A reference of no bytes is `{}`, so it is missing `name`. A static text cannot name the
stray key, so the extra-key refusal does not. An empty material is refused (`the material is EMPTY;
a secret must be non-empty (fail-closed)`). A resolved material is decoded straight into the host's buffer
(flagged secret) under no lease, and the plugin keeps no copy of it; a material over that buffer
gets FAILED with `needed` equal to its decoded length, error kind UNSET, no lease and no bytes
written; the host retries with that capacity. `release` always answers REFUSED because no lease
is granted. `check` also answers REFUSED: the plugin leaves config-time reference checking
unserved, and `resolve` judges each reference. These are outcomes, not promised error strings.
Each op requires its complete output record; a NULL or shorter output is FAULT, written nothing.

At most one instance, whose ops hold one lock (a `refresh` never races a `resolve`); at most
8 KiB of settings (as written), 1 KiB of material per value and 1 KiB for each name (both decoded),
and JSON nested at most 32 deep. `\u` escapes decode to UTF-8, a
surrogate pair to its 4 bytes; an unpaired surrogate is refused.

## Build

Against `busbar_plugin.h` from busbar at the commit in `.busbar-ref`
(`crates/busbar-contract/include/`):

The supported builds are Linux with GCC or Clang and macOS with Clang, using C11 atomics and
the generated header's 64-bit layouts. Windows toolchains are not currently qualified.

```bash
mkdir -p target
cc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -I <busbar>/crates/busbar-contract/include -o target/libbusbar_secret_c.so secret-c/*.c
```

On macOS use `-dynamiclib` and `target/libbusbar_secret_c.dylib`.

`.version` in the Statement is a literal (`"1.6.0"`, there is no Cargo here): bump it by hand at
release.

## Tests

CI (busbar's `plugin-ci.yml` at the pin, `plugin_lang: c`) builds the library as above, loads it
through busbar's plugin loader (`load_dropped`) and drives the `kind: secret` conformance script
over `secret-c/conformance.json`, with its RED arm (the sources rebuilt at another kind ABI are
refused). Locally, from a busbar checkout at the pin:

```bash
BUSBAR_DROPPED_LIB=$PWD/target/libbusbar_secret_c.so BUSBAR_DROPPED_SOURCES=$PWD/secret-c \
BUSBAR_DROPPED_SCRIPT=$PWD/secret-c/conformance.json \
  cargo run --manifest-path <busbar>/Cargo.toml --locked -p busbar-test-kit \
  --example dropped_conformance
```

The unit tests (`secret-c/tests/unit.c`, not part of the plugin) drive the door directly for
what the conformance script does not judge, including input field boundaries, refresh custody
and credential-bearing refusals. The current normal CI `cunit` check runs them under
ThreadSanitizer. To run them locally:

```bash
cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=thread -g -DBUSBAR_SECRET_C_UNIT \
  -I <busbar>/crates/busbar-contract/include -o /tmp/secret-c-unit \
  secret-c/busbar_secret_c.c secret-c/tests/unit.c -lpthread && /tmp/secret-c-unit
```

## License

Apache-2.0. See [LICENSE](LICENSE).
