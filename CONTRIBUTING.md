# Contributing to busbar-secret-c

Thanks for your interest in improving `busbar-secret-c`.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Layout

Every busbar plugin repo has the same skeleton. This one is a C plugin: `secret-c/` holds its `.c`
sources, ordinary tests and its declares file. It includes `busbar_plugin.h` and nothing
else, the header taken from busbar at the commit in `.busbar-ref`. The CI, release and community
files are rendered by `busbar-release plugin heal` from the fleet template (GetBusbar/busbar-release
`template/`) and [busbar's plugin registry](https://github.com/GetBusbar/busbar/blob/main/plugins.yaml);
change them there, not here.

## This repo tests itself against busbar

CI calls busbar's reusable `plugin-ci.yml` at the pinned commit. It validates the source pin,
compiles the actual library against the public header, runs the applicable signing checks and
executes this repository's ordinary `extra_test` command. `BUSBAR_PLUGIN_CDYLIB` names the fresh
library; `BUSBAR_CHECKOUT` names the pinned header checkout. A missing test command is a failure.

Keep behavior assertions with this implementation. The external C ABI witness is a separate test
input with its own fixed contract, not a generic test framework or a built-in secret provider.

## Before you open a pull request

Build it as the README's Build section does, and run its ordinary tests.
Add or update assertions for any behavior change, and update the README when you change
behavior or config. Keep commits focused and describe what changed, why, and how it was verified.
