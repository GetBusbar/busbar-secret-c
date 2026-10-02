# Contributing to busbar-secret-c

Thanks for your interest in improving `busbar-secret-c`.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [MIT](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Layout

Every busbar plugin repo has the same skeleton. This one is a C plugin: `secret-c/` holds its `.c`
sources, its `conformance.json` and its declares file. It includes `busbar_plugin.h` and nothing
else, the header taken from busbar at the commit in `.busbar-ref`. The CI, release and community
files are rendered by `busbar-release plugin sync` from the fleet template (GetBusbar/busbar-release
`template/`) and [busbar's plugin registry](https://github.com/GetBusbar/busbar/blob/main/plugins.yaml);
change them there, not here.

## This repo tests itself against busbar

CI runs the fleet's one harness, busbar's reusable `plugin-ci.yml`, at the busbar commit in
`.busbar-ref`, on its C path: the pin check (a Cargo.toml here is refused), the build from the
header alone with `-std=c11 -Wall -Wextra -Werror -pedantic`, the signing gate for the kinds it
covers, and busbar's `dropped_conformance` target, which loads the built library through busbar's
plugin loader, drives this kind's conformance script over `secret-c/conformance.json`, and keeps a
RED arm: the same sources rebuilt with `-DBUSBAR_PLUGIN_KIND_ABI=<another version>` must be
refused. The source states its kind ABI through `BUSBAR_PLUGIN_KIND_ABI` for that reason.

## Before you open a pull request

Build it as the README's Build section does, and run the conformance as its Tests section does.
Add or update `conformance.json` for any behavior change, and update the README when you change
behavior or config. Keep commits focused and describe what changed, why, and how it was verified.
