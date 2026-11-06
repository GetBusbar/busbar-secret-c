# C memory ABI integration test

This repository supplies the external C input for Busbar's header-only build, dynamic loading,
and ABI-refusal tests. It uses the secret ABI table to exercise host-owned buffers and lifecycle
calls. Its repository name and history remain available for reproducible test inputs.


## What it is for

The ABI fixture is written in C from busbar's generated header
(`busbar_plugin.h`) alone: no Rust, no busbar crate, no libc header, no allocator. It is decision
#84's witness (BUSBAR-1.6.0.md): a third party builds a busbar plugin from the header alone, and
busbar loads it through the same dropped-in door as every Rust plugin.

Its test settings contain named values, allowing tests to check exact buffer contents, custody,
refusal handling, and refresh behavior.

## Fixture input

The fixture Statement uses the `secret-c` alias:
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
Each op requires its complete output record; a NULL or shorter output is FAULT, written nothing
(a `close` so answered still wipes the materials and closes the instance, as the host takes it as
closed). `refresh`, `resolve` and `close` serve only the open instance: on any other pointer, or
after `close`, they are FAULT and touch nothing.

At most one instance, whose ops hold one lock (a `refresh` never races a `resolve`); at most
8 KiB of settings (as written), 1 KiB of material per value and 1 KiB for each name (both decoded),
and JSON nested at most 32 containers deep (the top object is the first; scalars add no level).
`\u` escapes decode to UTF-8, a
surrogate pair to its 4 bytes; an unpaired surrogate is refused. Raw bytes must be well-formed UTF-8
(no stray continuation byte, overlong form, surrogate or code point past U+10FFFF); other text
is refused as malformed JSON.

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

CI uses `plugin_lang: c` and `source_role: c_abi_test`. It builds from the public header, then runs
the ordinary loader integration target over the actual library. The target checks dynamic
loading and host-buffer exchange, exact rejection of older/newer kind ABIs, and manifest-kind
refusal. From a Busbar checkout at the pin:

```bash
BUSBAR_C_ABI_LIBRARY=$PWD/target/libbusbar_secret_c.so BUSBAR_C_ABI_SOURCES=$PWD/secret-c \
  cargo test --manifest-path <busbar>/Cargo.toml --locked -p busbar-plugin-loader --test c_abi
```

The unit tests (`secret-c/tests/unit.c`, not part of the plugin) drive the door directly for
input field boundaries, refresh custody
and credential-bearing refusals. No CI check builds or runs them yet; run them under
ThreadSanitizer locally:

```bash
cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=thread -g -DBUSBAR_SECRET_C_UNIT \
  -I <busbar>/crates/busbar-contract/include -o /tmp/secret-c-unit \
  secret-c/busbar_secret_c.c secret-c/tests/unit.c -lpthread && /tmp/secret-c-unit
```

The case that reads the dead stack for decoding scratch needs a build without
`-fsanitize=thread` (the sanitizer's own spills would fail it): run the same command once more
with `-fsanitize=address` in its place, which also catches a parser read past the end of
settings handed over at their exact length.

## License

Apache-2.0. See [LICENSE](LICENSE).
