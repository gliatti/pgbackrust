//! Config-resolution coverage for every command in `pgbr_command::dispatch`.
//!
//! The bar this suite enforces: *no command fails at config resolution*. Every
//! one of the 23 dispatch commands, given a reasonable argv, must make it
//! through the parse -> resolve -> `pgbackrust.conf` load -> default-resolution
//! -> validation pipeline and reach its command implementation. The command's
//! own runtime outcome (success, or a typed [`pgbr_command::CommandError`], or a
//! storage/spawn error) is *not* this suite's concern — what must never happen
//! is a *config-resolution* failure:
//!
//! - [`CliRunError::CliResolve`] — argv didn't resolve to the command/options,
//! - [`CliRunError::Load`] — the merge/default-resolution/validation step
//!   rejected the resolved invocation (the class the literal-default and
//!   depend-gating fixes targeted),
//! - [`CliRunError::Ini`] — `pgbackrust.conf` parse failure,
//! - [`CliRunError::StorageConfig`] — a required storage option was missing or
//!   had an unsupported value when building a backend.
//!
//! Each command is driven through the real `pgbr_cli::run_with_context` (the
//! same entry the binary uses), with a deterministic [`RuntimeContext`] so the
//! `default-type: dynamic` `bin` family resolves to a fixed path. A `--config`
//! pointing at a guaranteed-absent file keeps the host's `/etc/pgbackrust`
//! (if any) out of the picture: the loader falls back to an empty INI, so the
//! resolution exercised is purely the embedded `config.yaml` defaults.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pgbr_cli::{CliRunError, resolve_only, run_with_context};
use pgbr_config::RuntimeContext;

/// A `RuntimeContext` with a fixed exe path so dynamic `bin` defaults resolve
/// deterministically rather than depending on the test binary's location.
fn ctx() -> RuntimeContext {
    RuntimeContext {
        exe_path: Some("/usr/bin/pgbackrust".to_owned()),
    }
}

/// Classify a `run` result as either "reached dispatch" (the bar this suite
/// enforces) or "failed config resolution" (a failure of the kind we fix).
///
/// Returns `Err(reason)` only for the config-resolution failure classes; every
/// other outcome — `Ok(exit_code)`, a runtime `Command` error, a `Storage` /
/// `Protocol` / `NotSupportedYet` error — counts as *reached dispatch* and
/// returns `Ok(())`.
fn assert_reaches_dispatch(command: &str, result: Result<i32, CliRunError>) {
    match result {
        // Reached its implementation (or a runtime/backend error past resolution).
        Ok(_)
        | Err(CliRunError::Command(_) | CliRunError::Storage(_) | CliRunError::Protocol(_) | CliRunError::NotSupportedYet(_)) => {}
        // Config-resolution failures: the class this suite guards against.
        Err(err @ (CliRunError::CliResolve(_) | CliRunError::Load(_) | CliRunError::Ini(_) | CliRunError::StorageConfig(_))) => {
            panic!("command `{command}` failed CONFIG RESOLUTION (must reach dispatch): {err:?}");
        }
        // Embedded-schema / argv-tokenizer errors should never happen with a
        // well-formed argv against the shipped config.yaml.
        Err(other) => {
            panic!("command `{command}` produced an unexpected pre-dispatch error: {other:?}");
        }
    }
}

/// Which storage roots a command's option model accepts. `repo-path` is valid
/// for the whole `repo` option-group's command set (info, expire, verify,
/// backup, restore, …) but NOT for `start`/`stop`/`server*`; `pg-path` is valid
/// only for the PG-touching commands (backup, restore, check, stanza-*,
/// archive-*, manifest). Passing an option a command does not declare is itself
/// an `OptionNotValidForCommand` *resolution* error — so the argv has to match
/// the command's model. C ref: the `repo` / `pg-path` `command:` blocks in
/// `config.yaml`.
#[derive(Clone, Copy)]
struct Roots {
    repo: bool,
    pg: bool,
}

impl Roots {
    /// repo + pg (PG-touching commands).
    const BOTH: Self = Self { repo: true, pg: true };
    /// repo only (repo-only commands).
    const REPO: Self = Self { repo: true, pg: false };
    /// neither (start / stop / server*).
    const NONE: Self = Self { repo: false, pg: false };
}

/// Commands whose option model accepts `--lock-path`. See `config.yaml`'s
/// `lock-path` entry: only the commands listed there may carry the option, so
/// passing it to (say) `version` or `repo-ls` is itself an
/// `OptionNotValidForCommand` resolution error.
const LOCK_PATH_COMMANDS: &[&str] = &[
    "annotate",
    "archive-get",
    "archive-push",
    "backup",
    "expire",
    "info",
    "restore",
    "stanza-create",
    "stanza-delete",
    "stanza-upgrade",
    "start",
    "stop",
];

/// Run `command` with a per-command argv (stanza + the storage roots its model
/// accepts + `extra`), asserting it reaches dispatch.
fn check_command(command: &str, roots: Roots, extra: &[&str]) {
    let repo = tempfile::tempdir().expect("repo tempdir");
    let pg = tempfile::tempdir().expect("pg tempdir");
    // Always isolate `--lock-path` to a per-test tempdir for the commands
    // that accept it: `stop` writes `<lock-path>/<stanza>.stop` LOCALLY, and
    // `backup`/`archive-push`/… now gate on the same file, so a leaked sentinel
    // under the shared default `/tmp/pgbackrust` would break sibling tests
    // (e2e backup, lib.rs dispatch) in the same `cargo test` invocation.
    let lock = tempfile::tempdir().expect("lock tempdir");

    let mut args = vec![command.to_owned(), "--stanza=demo".to_owned()];
    if LOCK_PATH_COMMANDS.contains(&command) {
        args.push(format!("--lock-path={}", lock.path().display()));
    }
    if roots.repo {
        args.push(format!("--repo1-path={}", repo.path().display()));
    }
    if roots.pg {
        args.push(format!("--pg1-path={}", pg.path().display()));
    }
    for a in extra {
        args.push((*a).to_owned());
    }
    assert_reaches_dispatch(command, run_with_context(args, &ctx()));
}

// ---------------------------------------------------------------------------
// Informational commands (short-circuit before storage).
// ---------------------------------------------------------------------------

#[test]
fn version_reaches_dispatch() {
    // `version` short-circuits storage; argv carries nothing but the command.
    assert_reaches_dispatch("version", run_with_context(["version"], &ctx()));
}

#[test]
fn help_reaches_dispatch() {
    assert_reaches_dispatch("help", run_with_context(["help"], &ctx()));
}

// ---------------------------------------------------------------------------
// Repo-only / lifecycle commands (need a repo, tolerate a missing pg-path).
// ---------------------------------------------------------------------------

#[test]
fn info_reaches_dispatch() {
    check_command("info", Roots::REPO, &[]);
}

#[test]
fn start_reaches_dispatch() {
    // `start` / `stop` accept neither `repo-path` nor `pg-path` (the `repo`
    // group's command set excludes them), so the argv is just the stanza.
    check_command("start", Roots::NONE, &[]);
}

#[test]
fn stop_reaches_dispatch() {
    check_command("stop", Roots::NONE, &[]);
}

#[test]
fn expire_reaches_dispatch() {
    check_command("expire", Roots::REPO, &[]);
}

#[test]
fn verify_reaches_dispatch() {
    check_command("verify", Roots::REPO, &[]);
}

#[test]
fn repo_ls_reaches_dispatch() {
    // `repo-ls` takes an optional path parameter; the bare form lists the root.
    check_command("repo-ls", Roots::REPO, &[]);
}

#[test]
fn repo_rm_reaches_dispatch() {
    // `repo-rm` is parameter-allowed; give it a path to remove.
    check_command("repo-rm", Roots::REPO, &["some/path"]);
}

#[test]
fn annotate_reaches_dispatch() {
    // `annotate` needs a backup set + a key/value annotation; repo-only.
    check_command("annotate", Roots::REPO, &["--set=20240101-000000F", "--annotation=key=value"]);
}

#[test]
fn manifest_reaches_dispatch() {
    // `manifest` (internal) renders a backup's manifest; needs the set label.
    // It accepts `pg-path` (required: false) but reads from the repo, so the
    // repo root is the meaningful one.
    check_command("manifest", Roots::REPO, &["--set=20240101-000000F"]);
}

// ---------------------------------------------------------------------------
// Stanza lifecycle (need repo + pg).
// ---------------------------------------------------------------------------

#[test]
fn stanza_create_reaches_dispatch() {
    check_command("stanza-create", Roots::BOTH, &[]);
}

#[test]
fn stanza_upgrade_reaches_dispatch() {
    check_command("stanza-upgrade", Roots::BOTH, &[]);
}

#[test]
fn stanza_delete_reaches_dispatch() {
    check_command("stanza-delete", Roots::BOTH, &[]);
}

#[test]
fn check_reaches_dispatch() {
    check_command("check", Roots::BOTH, &[]);
}

// ---------------------------------------------------------------------------
// Backup / restore (need repo + pg).
// ---------------------------------------------------------------------------

#[test]
fn backup_reaches_dispatch() {
    check_command("backup", Roots::BOTH, &[]);
}

#[test]
fn restore_reaches_dispatch() {
    check_command("restore", Roots::BOTH, &[]);
}

// ---------------------------------------------------------------------------
// Archive commands (positional WAL parameter).
// ---------------------------------------------------------------------------

#[test]
fn archive_push_reaches_dispatch() {
    // `archive-push` takes the WAL segment path as a positional parameter and
    // accepts both repo + pg roots.
    let pg = tempfile::tempdir().expect("pg tempdir");
    let wal = pg.path().join("pg_wal").join("000000010000000000000001");
    std::fs::create_dir_all(wal.parent().unwrap()).expect("mk pg_wal");
    std::fs::write(&wal, b"wal").expect("seed wal segment");
    check_command("archive-push", Roots::BOTH, &[wal.to_str().unwrap()]);
}

#[test]
fn archive_get_reaches_dispatch() {
    // `archive-get` takes the WAL segment name + destination path.
    let pg = tempfile::tempdir().expect("pg tempdir");
    let dest = pg.path().join("dest-wal");
    check_command(
        "archive-get",
        Roots::BOTH,
        &["000000010000000000000001", dest.to_str().unwrap()],
    );
}

// ---------------------------------------------------------------------------
// repo-get / repo-put (positional repo-path parameter).
// ---------------------------------------------------------------------------

#[test]
fn repo_get_reaches_dispatch() {
    check_command("repo-get", Roots::REPO, &["backup.info"]);
}

#[test]
fn repo_put_reaches_dispatch() {
    // `repo-put` reads the object body from stdin and writes to the repo path.
    check_command("repo-put", Roots::REPO, &["uploaded.txt"]);
}

// ---------------------------------------------------------------------------
// Regression (GHSA-vq5g-8277-5pwc, CWE-22): `repo-ls` / `repo-get` / `repo-rm`
// took an absolute path parameter verbatim and did not neutralize `..`, so any
// host path reachable by the process could be listed, read or deleted. Every
// path parameter is now confined under `repoN-path`: a relative path is
// normalized lexically and a `..` escape is rejected; an absolute path is only
// accepted when it lies lexically under the repository root. Driven end to end
// through `run_with_context`, the same entry the binary uses.
// ---------------------------------------------------------------------------

/// Run a `repo-*` command against `repo_root` (as `--repo1-path`) with the
/// positional `params`, isolated from any host `pgbackrust.conf`.
fn run_repo_command(command: &str, repo_root: &std::path::Path, params: &[&str]) -> Result<i32, CliRunError> {
    let mut args = vec![
        "--config=/definitely/missing/pgbackrust.conf".to_owned(),
        command.to_owned(),
        "--stanza=demo".to_owned(),
        format!("--repo1-path={}", repo_root.display()),
    ];
    args.extend(params.iter().map(|p| (*p).to_owned()));
    run_with_context(args, &ctx())
}

/// Assert `result` is a rejection whose message carries `path validation`
/// (the confinement error), not a success nor an unrelated failure.
fn assert_path_validation_rejected(what: &str, result: Result<i32, CliRunError>) {
    match result {
        Ok(code) => panic!("`{what}` must be rejected (path outside the repository), got exit code {code}"),
        Err(err) => {
            let rendered = format!("{err} / {err:?}");
            assert!(
                rendered.contains("path validation"),
                "`{what}` must fail with a path-validation error, got: {rendered}"
            );
        }
    }
}

#[test]
fn repo_ls_host_root_rejected() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    assert_path_validation_rejected("repo-ls /", run_repo_command("repo-ls", repo.path(), &["/"]));
}

#[test]
fn repo_get_absolute_path_outside_repo_rejected() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    assert_path_validation_rejected(
        "repo-get /etc/hostname",
        run_repo_command("repo-get", repo.path(), &["/etc/hostname"]),
    );
}

#[test]
fn repo_get_parent_escape_rejected() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    // Rejected lexically, before any filesystem access: the error must be the
    // confinement one, not a not-found from the escaped target.
    assert_path_validation_rejected("repo-get ../../x", run_repo_command("repo-get", repo.path(), &["../../x"]));
}

#[test]
fn repo_rm_absolute_path_outside_repo_rejected() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    // A victim file in a SEPARATE tempdir (the `/tmp/outside` vector): it is
    // absolute and lexically outside the repository root.
    let outside = tempfile::tempdir().expect("outside tempdir");
    let victim = outside.path().join("outside");
    std::fs::write(&victim, b"must survive").expect("seed victim file");
    let victim_arg = victim.to_str().expect("utf-8 tempdir path");

    assert_path_validation_rejected(
        &format!("repo-rm {victim_arg}"),
        run_repo_command("repo-rm", repo.path(), &[victim_arg]),
    );
    assert!(victim.exists(), "repo-rm must not delete a file outside the repository");
}

#[test]
fn repo_ls_absolute_repo_root_accepted() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    std::fs::write(repo.path().join("backup.info"), b"[backrest]\n").expect("seed repo file");
    let root_arg = repo.path().to_str().expect("utf-8 tempdir path");

    match run_repo_command("repo-ls", repo.path(), &[root_arg]) {
        Ok(code) => assert_eq!(code, 0, "`repo-ls <repo root>` must succeed"),
        Err(err) => panic!("`repo-ls <repo root>` (absolute path AT the repository root) must be accepted: {err:?}"),
    }
}

// ---------------------------------------------------------------------------
// Server commands.
// ---------------------------------------------------------------------------

#[test]
fn server_ping_reaches_dispatch() {
    // `server-ping` connects to the default `127.0.0.1:8432`; with nothing
    // listening the connect is refused immediately, so dispatch is reached and
    // the command returns a runtime (connection) error — never a
    // config-resolution one.
    assert_reaches_dispatch(
        "server-ping",
        run_with_context(["--config=/definitely/missing/pgbackrust.conf", "server-ping"], &ctx()),
    );
}

// ---------------------------------------------------------------------------
// Regression: the universal config-location options (`--config`,
// `--config-path`, `--config-include-path`) declare NO `command:` block in
// config.yaml, so before the compile fix they resolved to an empty command set
// and were rejected for every command with `OptionNotValidForCommand`. The
// compile step now defaults a command-less option to "all commands except
// help/version" (C ref: `src/build/config/parse.c`). Confirm each resolves
// against representative commands rather than failing resolution.
// ---------------------------------------------------------------------------

#[test]
fn config_option_valid_for_a_command() {
    // `--config=<missing>` resolves (and the loader falls back to an empty INI)
    // rather than erroring with `OptionNotValidForCommand`.
    let repo = tempfile::tempdir().expect("repo tempdir");
    let cfg_path = repo.path().join("absent.conf");
    assert_reaches_dispatch(
        "info",
        run_with_context(
            [
                format!("--config={}", cfg_path.display()),
                "info".to_owned(),
                "--stanza=demo".to_owned(),
                format!("--repo1-path={}", repo.path().display()),
            ],
            &ctx(),
        ),
    );
}

#[test]
fn config_path_and_include_path_options_valid_for_a_command() {
    // `--config-path` and `--config-include-path` are the other command-less
    // options; both must resolve for a representative command.
    let repo = tempfile::tempdir().expect("repo tempdir");
    let repo_arg = format!("--repo1-path={}", repo.path().display());
    let cfg_path_arg = format!("--config-path={}", repo.path().display());
    let include_arg = format!("--config-include-path={}", repo.path().display());

    assert_reaches_dispatch(
        "verify",
        run_with_context(
            [
                "verify".to_owned(),
                "--stanza=demo".to_owned(),
                repo_arg,
                cfg_path_arg,
                include_arg,
            ],
            &ctx(),
        ),
    );
}

#[test]
fn server_resolves() {
    // `server` binds a TLS/TCP listener and blocks in an accept loop, so it
    // cannot be driven through `run` without hanging the test. Its config
    // resolution is what this suite cares about, so exercise the full
    // parse -> resolve -> load pipeline via `resolve_only` (which stops just
    // short of dispatch) and assert it does NOT fail config resolution.
    match resolve_only(["--config=/definitely/missing/pgbackrust.conf", "server"], &ctx()) {
        Ok(_) => {}
        Err(err @ (CliRunError::CliResolve(_) | CliRunError::Load(_) | CliRunError::Ini(_) | CliRunError::StorageConfig(_))) => {
            panic!("command `server` failed CONFIG RESOLUTION (must resolve): {err:?}");
        }
        Err(other) => panic!("command `server` produced an unexpected resolution error: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Regression (GHSA-5qj2-9x5v-7c87): `neutral-umask` is documented in help.xml
// as disableable with `--no-neutral-umask`, but the option lacked
// `negate: true` in config.yaml so the CLI rejected the negation. It must now
// resolve to `false`, while the default stays `true`.
// ---------------------------------------------------------------------------

/// Resolve `start --stanza=demo` plus `extra` (no dispatch: `resolve_only`)
/// and return the resolved `neutral-umask` value. `start` is a command the
/// option is valid for (`info` / `manifest` / `server*` exclude it).
fn resolved_neutral_umask(extra: &[&str]) -> Option<pgbr_config::OptionValue> {
    let mut args = vec![
        "--config=/definitely/missing/pgbackrust.conf".to_owned(),
        "start".to_owned(),
        "--stanza=demo".to_owned(),
    ];
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    let loaded = resolve_only(args, &ctx()).expect("`start` must resolve");
    loaded.options.get(&("neutral-umask".to_owned(), None)).cloned()
}

#[test]
fn no_neutral_umask_is_accepted_and_resolves_false() {
    assert_eq!(
        resolved_neutral_umask(&["--no-neutral-umask"]),
        Some(pgbr_config::OptionValue::Boolean(false)),
        "`--no-neutral-umask` must be accepted and resolve to false"
    );
}

#[test]
fn neutral_umask_defaults_to_true() {
    assert_eq!(
        resolved_neutral_umask(&[]),
        Some(pgbr_config::OptionValue::Boolean(true)),
        "`neutral-umask` must default to true"
    );
}
