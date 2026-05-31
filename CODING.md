# pgBackRest <br/> Coding Standards

This project is a Rust workspace. The standards below describe what the tooling
actually enforces. All commands run inside the `pgbackrust-dev` Docker image
(Rust is not installed on the host — see `CLAUDE.md`).

## Formatting (rustfmt)

Code is formatted with `rustfmt`; the configuration lives in `rustfmt.toml`:

- edition 2024
- `max_width = 132`
- 4-space indentation, no hard tabs
- Unix newlines
- field-init shorthand and `?` (try) shorthand preferred

Format and verify:

```
docker compose run --rm cargo fmt              # apply formatting
docker compose run --rm cargo fmt --check      # verify (CI gate)
```

## Linting (clippy)

Clippy is run with `--all-targets -- -D warnings`, which turns every clippy and
rustc warning into an error, including in test code:

```
docker compose run --rm cargo clippy --workspace --all-targets -- -D warnings
```

`--all-targets` is mandatory — without it clippy skips `#[cfg(test)]` code and
test-only lint regressions slip through.

The workspace lints are defined once in `[workspace.lints]` in the root
`Cargo.toml` and inherited by every crate:

- `clippy::all` is **denied**.
- `clippy::pedantic` and `clippy::nursery` are **warned** (hardened to errors by
  `-D warnings`).
- `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`,
  and `clippy::unimplemented` are **warned** in production code.
- `unused_must_use` is denied; `unsafe_op_in_unsafe_fn` is warned.
- A small set of pedantic lints that fight the codebase are allowed
  (`multiple_crate_versions`, `missing_errors_doc`, `missing_panics_doc`,
  `module_name_repetitions`).

Thresholds (`cognitive-complexity`, `type-complexity`, `too-many-arguments`)
live in `clippy.toml`.

### Tests may panic; production code may not

Tests are allowed to `unwrap` / `expect` / `panic` freely. Every crate root
opts in with:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
```

This keeps the lints active for production code while letting tests use the
concise idioms. Add this attribute to the crate root of any new crate.

## Idiomatic Rust

- Return `Result<T, Error>` and propagate with `?`. Do not `unwrap` / `expect` /
  `panic` in production paths — surface a typed `pgbr_error::Error` instead.
- Use `Drop` for cleanup (closing handles, freeing C resources) rather than
  manual teardown calls. This replaces the C `xxxFree()` / memory-context model.
- `unsafe` is confined to the few places that wrap C libraries (`pgbr-db` over
  libpq, `pgbr-storage` sftp over ssh2, the compression FFI). Keep `unsafe`
  blocks minimal, document the invariant each one upholds, and expose a safe API
  around them. Do not introduce new `unsafe` elsewhere.
- Prefer borrowing (`&str`, `&[u8]`) over owned types in signatures where the
  callee does not need ownership.

## Documentation comments

- Public items carry `///` doc comments.
- A function that returns `Result` documents its failure modes under an
  `# Errors` section.
- `unsafe fn`s document their safety contract under a `# Safety` section.
- Pure getters and other side-effect-free functions whose return value should
  not be ignored are marked `#[must_use]`.

```rust
/// Returns the resolved repository path for the stanza.
///
/// # Errors
///
/// Returns [`Error`] if the `repo-path` option is missing or invalid.
#[must_use = "the resolved path is the function's only output"]
pub fn repo_path(&self) -> Result<&str, Error> { ... }
```

## Tests

- Per-module unit tests live in a `#[cfg(test)] mod tests` block inside the crate
  they cover.
- Tests that require a live endpoint (cloud storage, a real PostgreSQL server)
  are marked `#[ignore]` and gated on environment variables so the default
  `cargo test --workspace` stays hermetic.

Run the full suite with:

```
docker compose run --rm cargo test --workspace
```
