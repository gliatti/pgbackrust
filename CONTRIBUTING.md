# pgBackRust <br/> Contributing

This fork is a from-scratch rewrite of pgBackRust in Rust. See `README.md` for an
overview and `CODING.md` for the coding standards. This document describes how to
get changes in.

## Development environment

**Rust is not installed on the host.** Everything (cargo, the test suite, the
gate) runs inside the `pgbackrust-dev` Docker image defined in `Dockerfile.dev`
and orchestrated by `docker-compose.yml`. `CLAUDE.md` documents the image,
pinned toolchain versions, and the named volumes that cache the Cargo registry
and `target/`.

First-time setup:

```
docker compose build dev
```

Common commands (all from the repo root):

```
docker compose run --rm cargo check --workspace                 # quick type-check
docker compose run --rm cargo build --workspace --release       # build the pgbackrust binary
docker compose run --rm cargo run -p pgbr-cli -- info           # run the binary
docker compose exec dev bash                                    # interactive shell in the dev container
```

## Workflow

1. Branch off **`eol`** (this is the branch all work targets; there is no `main`
   for this fork).
2. Make your change. Keep production code free of `unwrap` / `expect` / `panic`
   (see `CODING.md`); add or update tests in the owning crate's
   `#[cfg(test)] mod tests`.
3. Run the gate (below) until it is clean.
4. Open a pull request against **`eol`**.

## The gate (run before every commit)

These are the exact checks CI runs. A change is not ready until all three pass:

```
docker compose run --rm cargo fmt --check
docker compose run --rm cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm cargo test --workspace
```

`--all-targets` is required so clippy lints test code too.

## Triggering CI without a PR

`.github/workflows/test.yml` runs the gate on pushes/PRs to `eol` and on any
branch whose name ends in `-ci` or `-cig`. Renaming your branch to end in `-cig`
and pushing it to your fork runs the full matrix without opening a pull request.

## Adding a configuration option

Two hand-written files under `crates/pgbr-build/inputs/`:

1. `config.yaml` — defines the option (type, commands, command-roles, group,
   defaults, allow-list, secrets). Command-line-only options omit `section:`;
   config-file options set `section: global` or `stanza`. Group options like
   `repo` index to `repo1-foo`, `repo2-foo`, etc.
2. `help.xml` — an `<option>` entry with `<summary>` (ending in a period),
   `<text>`, and `<example>`.

Both files are embedded into `pgbr-build` at compile time, so a plain
`cargo build` picks up the change — there is no separate code-generation step.
Add resolution tests in `pgbr-config` for any new behavior.

## Submitting a pull request

- Give it a short, descriptive title and a comment explaining the purpose and any
  issue it resolves (link the GitHub issue if there is one).
- Confirm the gate passes.
- Target the **`eol`** branch.

## License

By contributing you agree that your contributions are licensed under the MIT
license, the same as the rest of the project (see [`LICENSE`](LICENSE)).

Thank you for contributing!
