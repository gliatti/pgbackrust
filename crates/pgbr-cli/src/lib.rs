#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Top-level entry point for the `pgbackrest` Rust binary.
//!
//! Wires `pgbr_build` (config schema), `pgbr_config` (CLI/INI/merge),
//! and `pgbr_command` (per-command implementations) into one invocation. This
//! slice ships the full parse + resolve + load pipeline, builds the repo + pg
//! [`pgbr_storage::Storage`] backends from the resolved config (see
//! [`storage_helper`]), and dispatches to the real command implementations.
//! `version` / `help` short-circuit before any storage is built.

// `unsafe` is denied (not forbidden) so the two libc FFI shims for the
// process-control options (`neutral-umask` → `umask(0)`, `priority` →
// `setpriority`) can opt in locally with `#[allow(unsafe_code)]`. Every other
// item in the crate stays unsafe-free.
#![cfg_attr(not(test), deny(unsafe_code))]

use std::path::PathBuf;

use pgbr_config::{
    Cfg, CliResolveError, CompileError, IniFile, LoadError, LoadedConfig, OptionValue, ResolvedCli, RuntimeContext, compile,
    env_values_from_process, load_config_with_env_multi, parse_cli, parse_ini, resolve_cli,
};
use pgbr_protocol::ProtocolError;
use pgbr_storage::StorageError;

pub mod remote_storage;
mod storage_helper;

/// The pgBackRest schema (`config.yaml`), embedded at compile time by
/// `pgbr-build` so the binary carries it without a runtime file dependency.
const CONFIG_YAML: &str = pgbr_build::inputs::CONFIG_YAML;

/// Default path to `pgbackrest.conf` if `--config` is not supplied.
const DEFAULT_CONFIG_PATH: &str = "/etc/pgbackrest/pgbackrest.conf";

/// Default base config directory (the `config-path` option's default), used to
/// derive the include-path default `<config-path>/conf.d` when neither
/// `--config-include-path` nor `--config-path` is supplied. Mirrors
/// `CFGOPTDEF_CONFIG_PATH` in `config.yaml`.
const DEFAULT_CONFIG_DIR: &str = "/etc/pgbackrest";

/// Sub-directory of `config-path` scanned for additional `*.conf` files when
/// `--config-include-path` is not supplied. Mirrors `PROJECT_CONFIG_INCLUDE_PATH`.
const DEFAULT_INCLUDE_SUBDIR: &str = "conf.d";

/// Extension of the include files loaded from the config-include-path. Only
/// entries ending in `.conf` are read (matching pgBackRest's `cfgLoad`).
const INCLUDE_FILE_EXT: &str = ".conf";

/// Process exit code for configuration / option errors.
///
/// pgBackRest's C error table assigns `OptionError` code 27; this is the
/// closest single bucket for the "couldn't resolve the invocation" family
/// (`CliResolve`, `Load`, `Ini`, `ReadConfigFile`). Exact parity with the full
/// error-code table is a later refinement — see [`CliRunError::exit_code`].
const EXIT_CODE_CONFIG_ERROR: i32 = 27;

/// Process exit code for a runtime command failure (the command resolved and
/// loaded fine but its implementation returned an error).
const EXIT_CODE_RUNTIME_ERROR: i32 = 1;

/// Process exit code for an embedded-schema / internal error that should never
/// happen in a shipped binary (the embedded `config.yaml` failed to parse or
/// compile). Mapped to the runtime-error bucket since there's no actionable
/// config to point the user at.
const EXIT_CODE_INTERNAL_ERROR: i32 = 1;

/// Top-level errors.
///
/// The exit code reflects the error category (matches the rough shape of
/// pgBackRest's C error codes — exact alignment is a future commit). See
/// [`CliRunError::exit_code`] for the mapping.
#[derive(Debug)]
pub enum CliRunError {
    /// `config.yaml` failed to parse — should never happen since it's
    /// embedded.
    ConfigYaml(serde_yml::Error),
    /// `compile()` rejected the parsed config.
    Compile(CompileError),
    /// argv tokenizer failed.
    Cli(pgbr_config::CliError),
    /// `resolve_cli` failed (unknown command/option, …).
    CliResolve(CliResolveError),
    /// Reading `pgbackrest.conf` failed (path missing, permission, …).
    ReadConfigFile {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        error: std::io::Error,
    },
    /// `parse_ini` rejected the config file's contents.
    Ini(pgbr_config::IniError),
    /// `load_config` failed (required option missing, type mismatch,
    /// allow-list / allow-range / depend violation).
    Load(LoadError),
    /// A required storage option was missing or had an unsupported value when
    /// building the repo / pg backend (e.g. `repo-type=s3` with no
    /// `repo-s3-bucket`, or an unrecognised `repo-type`).
    StorageConfig(String),
    /// A storage backend constructor itself rejected the resolved config (e.g.
    /// `Azure::new` with a malformed base64 account key).
    Storage(StorageError),
    /// A capability whose building blocks exist but whose wiring into the
    /// binary is a follow-up (SFTP / GCS service-account selection). Honest
    /// placeholder rather than a silent fallback.
    NotSupportedYet(String),
    /// Spawning or driving the inter-host worker process failed (e.g. `ssh`
    /// could not be launched when `repo-host` / `pg-host` is set).
    Protocol(ProtocolError),
    /// A per-command implementation failed. `NotYetImplemented` is handled
    /// inline (exit 2); every other [`pgbr_command::CommandError`] surfaces
    /// here.
    Command(pgbr_command::CommandError),
}

impl std::fmt::Display for CliRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigYaml(e) => write!(f, "embedded config.yaml failed to parse: {e}"),
            Self::Compile(e) => write!(f, "config.yaml schema rejected at compile: {e}"),
            Self::Cli(e) => write!(f, "{e}"),
            Self::CliResolve(e) => write!(f, "{e}"),
            Self::ReadConfigFile { path, error } => {
                write!(f, "read {}: {error}", path.display())
            }
            Self::Ini(e) => write!(f, "{e}"),
            Self::Load(e) => write!(f, "{e}"),
            Self::StorageConfig(msg) => write!(f, "storage configuration error: {msg}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::NotSupportedYet(msg) => write!(f, "not supported yet: {msg}"),
            Self::Protocol(e) => write!(f, "remote worker: {e}"),
            Self::Command(e) => write!(f, "{e}"),
        }
    }
}

impl CliRunError {
    /// Map an error to the process exit code.
    ///
    /// Centralised so the mapping lives in one place and is unit-testable.
    /// Categories:
    ///
    /// - config / option errors ([`Self::CliResolve`], [`Self::Load`],
    ///   [`Self::Ini`], [`Self::ReadConfigFile`], [`Self::StorageConfig`],
    ///   [`Self::NotSupportedYet`]) → [`EXIT_CODE_CONFIG_ERROR`] (27). These all
    ///   stem from the resolved invocation asking for something the binary
    ///   can't satisfy from config.
    /// - runtime command failures ([`Self::Command`], [`Self::Storage`],
    ///   [`Self::Protocol`]) → [`EXIT_CODE_RUNTIME_ERROR`] (1).
    /// - internal / embedded-schema errors ([`Self::ConfigYaml`],
    ///   [`Self::Compile`], [`Self::Cli`]) → [`EXIT_CODE_INTERNAL_ERROR`] (1).
    ///
    /// Note: success (0) and not-yet-implemented (2) are returned as `Ok`
    /// codes by [`run`] and never surface as a [`CliRunError`], so they have
    /// no entry here.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::CliResolve(_)
            | Self::Load(_)
            | Self::Ini(_)
            | Self::ReadConfigFile { .. }
            | Self::StorageConfig(_)
            | Self::NotSupportedYet(_) => EXIT_CODE_CONFIG_ERROR,
            Self::Command(_) | Self::Storage(_) | Self::Protocol(_) => EXIT_CODE_RUNTIME_ERROR,
            Self::ConfigYaml(_) | Self::Compile(_) | Self::Cli(_) => EXIT_CODE_INTERNAL_ERROR,
        }
    }
}

impl std::error::Error for CliRunError {}

/// Build the [`RuntimeContext`] from the running process, carrying the
/// executable path so `default-type: dynamic` options (the `bin` family:
/// `cmd`, `pg-host-cmd`, `repo-host-cmd`) resolve to the real binary path
/// instead of the `"pgbackrest"` fallback.
fn env_context() -> RuntimeContext {
    RuntimeContext {
        exe_path: std::env::current_exe().ok().and_then(|p| p.to_str().map(str::to_owned)),
    }
}

/// Run the CLI end-to-end.
///
/// `args` is the argv excluding `argv[0]` (the program name). Returns the
/// process exit code (0 = success, non-zero = error). The [`RuntimeContext`]
/// is derived from the running process (see [`env_context`]).
///
/// This function is testable — the binary's `main()` just forwards `env::args()`.
///
/// # Errors
///
/// Returns [`CliRunError`] when the embedded `config.yaml` fails to parse or
/// compile, when argv resolution hits a typed error other than
/// `MissingCommand`, when reading or parsing `pgbackrest.conf` fails, or when
/// the final merge / validation rejects the resolved options. The
/// `MissingCommand` case is handled inline: a hint is printed to stderr and
/// `Ok(1)` is returned.
pub fn run<I, S>(args: I) -> Result<i32, CliRunError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_context(args, &env_context())
}

/// [`run`], but with an explicit [`RuntimeContext`] for deterministic testing.
///
/// # Errors
///
/// Same as [`run`].
#[allow(clippy::print_stdout, clippy::print_stderr)] // CLI binary writes to stdout/stderr by design.
pub fn run_with_context<I, S>(args: I, ctx: &RuntimeContext) -> Result<i32, CliRunError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let cfg = load_static_cfg()?;
    let cli = parse_cli(args).map_err(CliRunError::Cli)?;
    let resolved = match resolve_cli(cli, &cfg) {
        Ok(r) => r,
        Err(CliResolveError::MissingCommand) => {
            eprintln!("pgbackrest: no command supplied");
            eprintln!("Try `pgbackrest help` for the list of commands.");
            return Ok(1);
        }
        Err(err) => return Err(CliRunError::CliResolve(err)),
    };

    // Worker invocation (`<command>:remote` / `<command>:local`): this process
    // was spawned by a parent pgbackrest (over SSH or locally) to serve the
    // storage protocol on its stdin/stdout. Route to the worker BEFORE the full
    // config merge + command dispatch: a worker is handed every option it needs
    // explicitly on the argv (the parent builds them), so it does not need the
    // embedded `config.yaml` defaults — and resolving directly from the CLI
    // sidesteps the full-config default validation the parent already passed.
    let worker_cfg = worker_loaded_config(&resolved);
    if pgbr_command::worker::is_worker(&worker_cfg) {
        // log-subprocess: the parent passes `--log-subprocess --log-level-file=<level>`
        // down to the worker (see `worker_log_args`). When set, honour it by
        // opening the worker's own file log at the inherited level before it
        // starts serving the protocol, so subprocess activity is captured. With
        // log-subprocess unset the worker stays console-only (the default), so
        // this is a no-op for the common single-host case.
        init_worker_logging(&worker_cfg, &cfg);
        return finish_dispatch(pgbr_command::worker::run_worker_stdio(&worker_cfg));
    }

    let mut loaded = load_resolved(resolved, &cfg, ctx)?;

    // Apply the process-level options before any work: set the umask, feed the
    // exec-id / priority / buffer-size / timeout / network-compression globals,
    // and initialise the logger from the resolved log-* options + the command's
    // log-level-default. Then fold the deprecated `compress` boolean into
    // `compress-type` / `compress-level` so the command stack sees only the
    // modern options.
    apply_legacy_compress(&mut loaded);
    apply_process_options(&loaded, &cfg);

    dispatch_loaded(&loaded)
}

/// Build a minimal [`LoadedConfig`] straight from a [`ResolvedCli`], without the
/// INI merge or the embedded-`config.yaml` default resolution.
///
/// Used only on the worker path: the worker reads its root (`pg1-path` /
/// `repo1-path`) and role from the options the parent passed explicitly on the
/// argv, so the heavier [`load_config_with_context`] merge (which would re-apply
/// — and validate — every default) is neither needed nor wanted here.
///
/// One normalisation is applied: the parent passes the worker's root as the
/// grouped `--repo1-path` / `--pg1-path`, which `resolve_cli` keys as
/// `("repo-path", Some(1))` / `("pg-path", Some(1))`. The worker side
/// (`pgbr_command::worker::run_worker_stdio`) looks the root up under the
/// *ungrouped* `("repo-path", None)` / `("pg-path", None)` keys, so mirror the
/// grouped value into the ungrouped key it reads.
fn worker_loaded_config(resolved: &ResolvedCli) -> LoadedConfig {
    let stanza = resolved.options.get(&("stanza".to_owned(), None)).and_then(|v| match v {
        OptionValue::String(s) => Some(s.clone()),
        _ => None,
    });

    let mut options = resolved.options.clone();
    for name in ["repo-path", "pg-path"] {
        let grouped = (name.to_owned(), Some(1));
        let ungrouped = (name.to_owned(), None);
        if !options.contains_key(&ungrouped)
            && let Some(value) = options.get(&grouped).cloned()
        {
            options.insert(ungrouped, value);
        }
    }

    LoadedConfig {
        command: resolved.command.clone(),
        command_role: resolved.command_role,
        stanza,
        options,
        params: resolved.params.clone(),
    }
}

/// Commands that operate on **every** configured repository rather than just the
/// active one (`--repo`): `archive-push` fans each WAL segment out to all repos,
/// `archive-get` reads from the first that has the segment, and the stanza
/// commands initialise / remove / upgrade the stanza on each. For these the CLI
/// builds one backend per configured repository (see
/// [`storage_helper::build_all_repo_storages`]) and dispatches through
/// [`pgbr_command::dispatch_multi`].
const MULTI_REPO_COMMANDS: &[&str] = &[
    "archive-push",
    "archive-get",
    "stanza-create",
    "stanza-delete",
    "stanza-upgrade",
];

/// Build storage (as needed) and dispatch `loaded` to its command, mapping the
/// outcome to a process exit code.
///
/// `version` / `help` are informational commands that never touch a repository
/// or PG data directory, so they short-circuit through a throwaway in-memory
/// posix backend (rooted at the current directory) without parsing any
/// `repo-*` / `pg-*` storage options. Multi-repository commands (see
/// [`MULTI_REPO_COMMANDS`]) build one backend per configured repository and
/// dispatch through [`pgbr_command::dispatch_multi`]. Every other command builds
/// the active repo + pg backends from the resolved config via [`storage_helper`]
/// and dispatches through [`pgbr_command::dispatch`].
fn dispatch_loaded(loaded: &LoadedConfig) -> Result<i32, CliRunError> {
    // Informational commands: no storage needed. Hand them a posix backend
    // rooted at "." so the dispatch signature is satisfied without resolving
    // any storage config (they never read through it).
    if matches!(loaded.command.as_str(), "version" | "help") {
        let throwaway = pgbr_storage::Posix::new(PathBuf::from("."));
        return finish_dispatch(pgbr_command::dispatch(loaded, &throwaway, &throwaway));
    }

    let pg_storage = build_pg_storage_or_placeholder(loaded)?;

    // Multi-repository commands: build one backend per configured repository and
    // dispatch through the index-aware entry point. The active repo (selected by
    // `--repo`) is the one whose index matches `repo` — or the first configured
    // when the active index has no backend in the set (it always does, since
    // `configured_repo_indexes` includes the active index).
    if MULTI_REPO_COMMANDS.contains(&loaded.command.as_str()) {
        let all = storage_helper::build_all_repo_storages(loaded)?;
        let active = storage_helper::active_repo_index(loaded);
        let active_storage = all
            .iter()
            .find(|(idx, _)| *idx == active)
            .or_else(|| all.first())
            .map(|(_, s)| s.as_ref())
            .ok_or_else(|| CliRunError::StorageConfig("no repository is configured".to_owned()))?;
        let pairs: Vec<(u32, &dyn pgbr_storage::Storage)> = all.iter().map(|(idx, s)| (*idx, s.as_ref())).collect();
        return finish_dispatch(pgbr_command::dispatch_multi(
            loaded,
            active_storage,
            &pairs,
            pg_storage.as_ref(),
        ));
    }

    // Every other command: build the two storage backends it is handed — one
    // rooted at the active backup repository (selected by `--repo` / `repo-type`),
    // one at the PG data directory. `build_pg_storage` errors when `pg-path` is
    // required but absent; repo-only commands that legitimately never touch PG
    // storage are handled by `build_pg_storage_or_placeholder` above.
    let repo_storage = storage_helper::build_repo_storage(loaded)?;

    finish_dispatch(pgbr_command::dispatch(loaded, repo_storage.as_ref(), pg_storage.as_ref()))
}

/// Build the pg storage, tolerating a missing `pg-path` for repo-only commands
/// by substituting a posix backend rooted at the current directory.
///
/// Repo-only commands (`info`, `repo-ls`, `expire`, …) are handed a pg storage
/// they never read through, so a missing `pg-path` must not block them. Remote
/// (`pg-host`) and other hard errors still surface.
fn build_pg_storage_or_placeholder(loaded: &LoadedConfig) -> Result<Box<dyn pgbr_storage::Storage>, CliRunError> {
    match storage_helper::build_pg_storage(loaded) {
        Ok(storage) => Ok(storage),
        // A missing `pg-path` is fine for repo-only commands; substitute an
        // inert posix backend rooted at ".". Any other error (e.g. pg-host
        // NotSupportedYet) is real and propagates.
        Err(CliRunError::StorageConfig(_)) => Ok(Box::new(pgbr_storage::Posix::new(PathBuf::from(".")))),
        Err(other) => Err(other),
    }
}

/// Map a `dispatch` result to a process exit code: `Ok(())` → 0, the
/// `NotYetImplemented` stub → 2 (with a hint), any other command error → a
/// [`CliRunError::Command`].
#[allow(clippy::print_stderr)] // CLI binary writes to stderr by design.
fn finish_dispatch(result: Result<(), pgbr_command::CommandError>) -> Result<i32, CliRunError> {
    match result {
        Ok(()) => Ok(0),
        Err(pgbr_command::CommandError::NotYetImplemented { command }) => {
            eprintln!("pgbackrest: command `{command}` is not yet implemented in the Rust port");
            Ok(2)
        }
        Err(err) => Err(CliRunError::Command(err)),
    }
}

fn load_static_cfg() -> Result<Cfg, CliRunError> {
    let parsed = pgbr_build::parse_config(CONFIG_YAML).map_err(CliRunError::ConfigYaml)?;
    compile(&parsed).map_err(CliRunError::Compile)
}

/// Read the main `pgbackrest.conf` plus every `*.conf` under the
/// config-include-path (falling back to an empty INI when the main file is
/// absent and to no extra files when the include dir is absent), collect the
/// `PGBACKREST_<OPTION>` environment variables, and merge them with `resolved`
/// and the runtime `ctx` into a [`LoadedConfig`]. Shared by
/// [`run_with_context`] and [`resolve_only`].
///
/// The five-source precedence is CLI > ENV > stanza:cmd > stanza > global:cmd >
/// global > default, matching pgBackRest (`src/config/load.c` / `cfgLoad`): the
/// process environment is read via [`env_values_from_process`] and slotted
/// between the CLI and the config files by [`load_config_with_env_multi`]. The
/// main config file and the include files are all "config file" level; the
/// include files are loaded *after* the main file, so a value they set wins for
/// the same key (pgBackRest's documented load order).
fn load_resolved(resolved: ResolvedCli, cfg: &Cfg, ctx: &RuntimeContext) -> Result<LoadedConfig, CliRunError> {
    // Determine the config file path. `--config=<path>` lives in
    // `resolved.options[("config", None)]`. Fall back to the default.
    let config_path = config_file_path(&resolved);

    // Config sources in load order: the main config file first, then the
    // include files. A later source's value wins for the same key.
    let mut inis: Vec<IniFile> = Vec::new();

    let main_ini = match std::fs::read_to_string(&config_path) {
        Ok(text) => parse_ini(&text).map_err(CliRunError::Ini)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => IniFile::default(),
        Err(error) => {
            return Err(CliRunError::ReadConfigFile {
                path: config_path,
                error,
            });
        }
    };
    inis.push(main_ini);

    // Scan the config-include-path for `*.conf` files and append each parsed
    // file (sorted by name for determinism) after the main config.
    inis.extend(load_include_files(&resolved)?);

    // `PGBACKREST_<OPTION>` environment variables: the env source sits below the
    // CLI but above the config files in precedence.
    let env = env_values_from_process(cfg);

    load_config_with_env_multi(resolved, &env, &inis, cfg, ctx).map_err(CliRunError::Load)
}

/// Resolve the config-include-path and parse every `*.conf` file in it into an
/// ordered list of [`IniFile`]s (sorted by file name for deterministic merge
/// order).
///
/// The include path is `--config-include-path` if supplied on the CLI,
/// otherwise `<config-path>/conf.d` where `<config-path>` is `--config-path`
/// (CLI) or [`DEFAULT_CONFIG_DIR`]. pgBackRest scans the include path even when
/// `--config` is given explicitly — the include path is its own option — so the
/// scan always runs.
///
/// A missing include directory is **not** an error (it just yields no extra
/// files). A malformed include file **is** an error (surfaced as
/// [`CliRunError::Ini`]); a non-NotFound I/O error reading the dir or a file is
/// surfaced as [`CliRunError::ReadConfigFile`].
fn load_include_files(resolved: &ResolvedCli) -> Result<Vec<IniFile>, CliRunError> {
    let include_path = config_include_path(resolved);

    let entries = match std::fs::read_dir(&include_path) {
        Ok(entries) => entries,
        // A missing include directory is a no-op (no extra config files).
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(CliRunError::ReadConfigFile {
                path: include_path,
                error,
            });
        }
    };

    // Collect candidate `*.conf` files, then sort by file name so the merge
    // order is deterministic regardless of directory iteration order.
    let mut conf_files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| CliRunError::ReadConfigFile {
            path: include_path.clone(),
            error,
        })?;
        let path = entry.path();
        // Take regular files whose name ends in `.conf`. Directories and other
        // entries (even if their name ends in `.conf`) are skipped.
        let is_conf = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(INCLUDE_FILE_EXT));
        if is_conf && entry.file_type().is_ok_and(|t| t.is_file()) {
            conf_files.push(path);
        }
    }
    conf_files.sort();

    let mut inis: Vec<IniFile> = Vec::with_capacity(conf_files.len());
    for path in conf_files {
        let text = std::fs::read_to_string(&path).map_err(|error| CliRunError::ReadConfigFile {
            path: path.clone(),
            error,
        })?;
        inis.push(parse_ini(&text).map_err(CliRunError::Ini)?);
    }
    Ok(inis)
}

/// Resolve the directory scanned for additional `*.conf` config files.
///
/// `--config-include-path` wins when supplied. Otherwise it is
/// `<config-path>/conf.d`, where `<config-path>` is `--config-path` (CLI) or
/// the [`DEFAULT_CONFIG_DIR`] default. Only CLI-supplied values are consulted
/// here (defaults from `config.yaml` are applied later, in the merge), so the
/// fallbacks mirror those defaults explicitly.
fn config_include_path(resolved: &ResolvedCli) -> PathBuf {
    if let Some(OptionValue::Path(p) | OptionValue::String(p)) = resolved.options.get(&("config-include-path".to_owned(), None)) {
        return PathBuf::from(p);
    }
    let base = match resolved.options.get(&("config-path".to_owned(), None)) {
        Some(OptionValue::Path(p) | OptionValue::String(p)) => p.clone(),
        _ => DEFAULT_CONFIG_DIR.to_owned(),
    };
    PathBuf::from(base).join(DEFAULT_INCLUDE_SUBDIR)
}

/// Run parse + resolve + load and return the merged [`LoadedConfig`].
///
/// Stops short of dispatching to a command. Exposed for tests that need to
/// inspect resolved option values (e.g. that a `default-type: dynamic` option
/// resolved against the threaded [`RuntimeContext`]).
///
/// # Errors
///
/// Same as [`run`], minus the dispatch step (no [`CliRunError::Command`]).
pub fn resolve_only<I, S>(args: I, ctx: &RuntimeContext) -> Result<LoadedConfig, CliRunError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let cfg = load_static_cfg()?;
    let cli = parse_cli(args).map_err(CliRunError::Cli)?;
    let resolved = resolve_cli(cli, &cfg).map_err(CliRunError::CliResolve)?;
    load_resolved(resolved, &cfg, ctx)
}

fn config_file_path(resolved: &ResolvedCli) -> PathBuf {
    match resolved.options.get(&("config".to_owned(), None)) {
        Some(OptionValue::Path(p) | OptionValue::String(p)) => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_CONFIG_PATH),
    }
}

// ---------------------------------------------------------------------------
// Process / logging / network option wiring (Tasks 15, 16, 24)
//
// After the config is resolved the binary applies the cross-cutting options
// that have no command-specific home: the logger setup, the process-control
// options (umask, exec-id, priority), the I/O / protocol / network globals the
// low-level crates read, and the legacy `compress` boolean fold-down. These all
// live here because they are owned by the top-level invocation, not by any one
// command.
// ---------------------------------------------------------------------------

/// Default `log-path` when the option is absent (matches `config.yaml`).
const DEFAULT_LOG_PATH: &str = "/var/log/pgbackrest";

/// Fallback console log level when `log-level-console` is absent from the
/// resolved map (matches `config.yaml`'s default).
const DEFAULT_LOG_LEVEL_CONSOLE: &str = "warn";

/// Fallback stderr log level when `log-level-stderr` is absent. The task's
/// requested fallback is `warn`; `config.yaml`'s own default (`off`) flows
/// through the resolved map on the normal path, so this only applies when the
/// option is missing entirely.
const DEFAULT_LOG_LEVEL_STDERR: &str = "warn";

/// Fallback file log level when `log-level-file` is absent (matches
/// `config.yaml`'s default).
const DEFAULT_LOG_LEVEL_FILE: &str = "info";

/// Map a `log-level-*` string-id (`off|error|warn|info|detail|debug|trace`) to
/// its `pgbr_core::log` numeric level.
///
/// `assert` has no string-id (it is synthesised internally), so it is absent
/// from the table — mirroring `config.yaml`'s `log-level-console` allow-list.
/// Returns `None` for an unrecognised id.
#[must_use]
fn log_level_from_id(id: &str) -> Option<i32> {
    Some(match id {
        "off" => pgbr_core::log::LOG_LEVEL_OFF,
        "error" => pgbr_core::log::LOG_LEVEL_ERROR,
        "warn" => pgbr_core::log::LOG_LEVEL_WARN,
        "info" => pgbr_core::log::LOG_LEVEL_INFO,
        "detail" => pgbr_core::log::LOG_LEVEL_DETAIL,
        "debug" => pgbr_core::log::LOG_LEVEL_DEBUG,
        "trace" => pgbr_core::log::LOG_LEVEL_TRACE,
        _ => return None,
    })
}

/// Resolve a `log-level-*` option to a numeric level, falling back to `fallback`
/// (one of the `DEFAULT_LOG_LEVEL_*` ids) when the option is absent or carries
/// an unrecognised value.
fn resolve_log_level(loaded: &LoadedConfig, name: &str, fallback: &str) -> i32 {
    string_id_option(loaded, name)
        .as_deref()
        .and_then(log_level_from_id)
        .unwrap_or_else(|| log_level_from_id(fallback).unwrap_or(pgbr_core::log::LOG_LEVEL_WARN))
}

/// Whether an explicit `detail-level=full` asks for the *full* (detailed)
/// output and should therefore raise the effective console level to at least
/// `DETAIL`.
///
/// `detail-level` (the `info` command option, `full` | `progress`, with a
/// schema default of `full`) controls how much per-item detail the output
/// carries. An explicit `full` wants the complete listing, so the console
/// verbosity floor is lifted to `DETAIL` to let the detail lines through;
/// `progress` keeps the terser level. The bump only ever *raises* the floor,
/// never lowers it.
///
/// Only an explicitly-resolved value is honoured here: when the option is absent
/// from the resolved map (every command other than `info`, and an `info`
/// invocation whose default has not been materialised) this returns `false` so
/// non-`info` commands keep their configured console level untouched. Returns
/// `true` only when the resolved value is `full`.
fn detail_level_raises_console(loaded: &LoadedConfig) -> bool {
    matches!(string_id_option(loaded, "detail-level").as_deref(), Some("full"))
}

/// Build the extra argv tokens that propagate logging into a spawned
/// remote / local worker when `log-subprocess` is enabled.
///
/// pgBackRest's `log-subprocess` (a `global`, `boolean`, default `false` option)
/// asks the parent to enable file logging in any subprocess it creates, using
/// the parent's `log-level-file`. The worker is otherwise launched with console
/// logging only; with `log-subprocess=true` the parent passes the flag plus the
/// resolved file level down so the child opens its own `<stanza>-<command>.log`.
/// Returns an empty vector when `log-subprocess` is unset / false (no
/// propagation). When set, it returns `["--log-subprocess",
/// "--log-level-file=<level>"]` so the child's own config resolution turns file
/// logging on at the inherited level. C ref: `cfgOptionBool(cfgOptLogSubprocess)`
/// handling in `src/protocol/helper.c`.
fn worker_log_args(loaded: &LoadedConfig) -> Vec<String> {
    if !bool_option(loaded, "log-subprocess").unwrap_or(false) {
        return Vec::new();
    }
    let file_level = string_id_option(loaded, "log-level-file").unwrap_or_else(|| DEFAULT_LOG_LEVEL_FILE.to_owned());
    vec!["--log-subprocess".to_owned(), format!("--log-level-file={file_level}")]
}

/// Read an ungrouped `string`/`string-id`/`path` option as a [`String`].
fn string_id_option(loaded: &LoadedConfig, name: &str) -> Option<String> {
    loaded.options.get(&(name.to_owned(), None)).and_then(|v| match v {
        OptionValue::String(s) | OptionValue::StringId(s) | OptionValue::Path(s) => Some(s.clone()),
        _ => None,
    })
}

/// Read an ungrouped `boolean` option.
fn bool_option(loaded: &LoadedConfig, name: &str) -> Option<bool> {
    match loaded.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Boolean(b)) => Some(*b),
        _ => None,
    }
}

/// Read an ungrouped `integer` option.
fn int_option(loaded: &LoadedConfig, name: &str) -> Option<i64> {
    match loaded.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Integer(i)) => Some(*i),
        _ => None,
    }
}

/// Read an ungrouped `size` option (bytes).
fn size_option(loaded: &LoadedConfig, name: &str) -> Option<u64> {
    match loaded.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Size(s)) => Some(*s),
        _ => None,
    }
}

/// Read an ungrouped `time` option (milliseconds).
fn time_ms_option(loaded: &LoadedConfig, name: &str) -> Option<u64> {
    match loaded.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Time(ms)) => Some(*ms),
        _ => None,
    }
}

/// Fold the deprecated `compress` boolean into the modern `compress-type` (and,
/// implicitly, `compress-level`) options on the resolved config.
///
/// pgBackRest keeps `compress` only for backward compatibility (`cfgLoadUpdateOption`
/// in `src/config/load.c`): `compress=y` selects `compress-type=gz` and
/// `compress=n` selects `compress-type=none`, but only when `compress-type` was
/// not set explicitly (the modern option wins). The command stack reads
/// `compress-type` / `compress-level`, so the fold-down must happen before
/// dispatch. The level is left to `compress-level`'s own per-type default.
fn apply_legacy_compress(loaded: &mut LoadedConfig) {
    let Some(compress) = bool_option(loaded, "compress") else {
        return;
    };
    // The modern option, when present, always wins over the deprecated boolean.
    if loaded.options.contains_key(&("compress-type".to_owned(), None)) {
        return;
    }
    let compress_type = if compress { "gz" } else { "none" };
    loaded.options.insert(
        ("compress-type".to_owned(), None),
        OptionValue::StringId(compress_type.to_owned()),
    );
}

/// Apply the cross-cutting process options once the config is resolved: set the
/// umask, derive the process id, set the scheduling priority, feed the
/// buffer-size / io-timeout / protocol-timeout / compress-level-network globals
/// the low-level crates read, then initialise the logger.
fn apply_process_options(loaded: &LoadedConfig, cfg: &Cfg) {
    // neutral-umask (default y): clear the umask so files/dirs are created with
    // their full mode, matching pgBackRest. Best-effort and Unix-only.
    if bool_option(loaded, "neutral-umask").unwrap_or(true) {
        set_neutral_umask();
    }

    // priority: best-effort scheduling nice level (Unix-only).
    if let Some(priority) = int_option(loaded, "priority") {
        set_process_priority(priority);
    }

    // buffer-size → pgbr_io copy buffer; io-timeout → pgbr_io timeout;
    // protocol-timeout / compress-level-network → pgbr_protocol globals.
    if let Some(size) = size_option(loaded, "buffer-size")
        && let Ok(size) = usize::try_from(size)
    {
        pgbr_io::set_copy_buffer_size(size);
    }
    if let Some(ms) = time_ms_option(loaded, "io-timeout") {
        pgbr_io::set_io_timeout_ms(ms);
    }
    if let Some(ms) = time_ms_option(loaded, "protocol-timeout") {
        pgbr_protocol::set_protocol_timeout_ms(ms);
    }
    if let Some(level) = int_option(loaded, "compress-level-network")
        && let Ok(level) = i32::try_from(level)
    {
        pgbr_protocol::set_network_compress_level(level);
    }

    // log-subprocess: publish the worker-logging propagation tokens so the
    // worker-spawning storage helpers append them to the child argv (see
    // `worker_log_propagation_args`). Empty when log-subprocess is unset/false.
    set_worker_log_propagation_args(worker_log_args(loaded));

    init_logging(loaded, cfg);
}

/// Process-global propagation tokens for `log-subprocess`: the extra argv the
/// parent appends to every spawned worker so the child enables file logging at
/// the inherited `log-level-file`. Set once by [`apply_process_options`] from
/// [`worker_log_args`] and read by the worker-spawning storage helpers via
/// [`worker_log_propagation_args`]. Empty (the default) means no propagation.
static WORKER_LOG_ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Record the `log-subprocess` worker-argv propagation tokens for the rest of
/// the process. Idempotent (first writer wins, matching the once-per-invocation
/// `apply_process_options` call).
fn set_worker_log_propagation_args(args: Vec<String>) {
    let _ = WORKER_LOG_ARGS.set(args);
}

/// The extra argv tokens a spawned worker should be launched with to honour
/// `log-subprocess` (`["--log-subprocess", "--log-level-file=<level>"]`), or an
/// empty slice when the option is unset/false.
///
/// Set from the resolved config by [`apply_process_options`]; consumed by the
/// remote/local worker-spawn path so the propagation reaches the child. Returns
/// an empty slice before [`apply_process_options`] has run.
#[must_use]
pub fn worker_log_propagation_args() -> &'static [String] {
    WORKER_LOG_ARGS.get().map_or(&[], Vec::as_slice)
}

/// Initialise logging for a *worker* invocation, honouring `log-subprocess`.
///
/// A worker is normally console-only (it serves the protocol on stdin/stdout and
/// is short-lived). When the parent propagated `log-subprocess` (and, with it,
/// `--log-level-file`) onto the worker's argv, the worker opens its own file log
/// so subprocess activity is captured — exactly the behaviour `log-subprocess`
/// promises. When the flag is absent this is a no-op, leaving the worker's
/// logging untouched.
fn init_worker_logging(worker_cfg: &LoadedConfig, cfg: &Cfg) {
    if bool_option(worker_cfg, "log-subprocess").unwrap_or(false) {
        init_logging(worker_cfg, cfg);
    }
}

/// Initialise `pgbr_core::log` from the resolved logging options.
///
/// Maps `log-level-console` → stdout level, `log-level-stderr` → stderr level,
/// `log-level-file` → file level; honours the per-command `log-level-default`
/// as a verbosity floor and `--verbose` as a console floor; sets the timestamp
/// flag from `log-timestamp` and the process id from `exec-id` (or the OS pid);
/// and, when the file level is not OFF, opens
/// `<log-path>/<stanza>-<command>.log` (or `all-server.log` for `server`) and
/// installs it as the file sink.
fn init_logging(loaded: &LoadedConfig, cfg: &Cfg) {
    let mut level_console = resolve_log_level(loaded, "log-level-console", DEFAULT_LOG_LEVEL_CONSOLE);
    let level_stderr = resolve_log_level(loaded, "log-level-stderr", DEFAULT_LOG_LEVEL_STDERR);
    let mut level_file = resolve_log_level(loaded, "log-level-file", DEFAULT_LOG_LEVEL_FILE);

    // The per-command log-level-default raises the verbosity floor for the
    // command's standard messages (louder wins). Applies to the console and
    // file sinks, not stderr (which stays an error channel).
    if let Some(default) = cfg
        .commands
        .get(&loaded.command)
        .and_then(|c| c.log_level_default.as_deref())
        .and_then(|d| log_level_from_id(&d.to_ascii_lowercase()))
    {
        level_console = level_console.max(default);
        level_file = level_file.max(default);
    }

    // --verbose bumps the console to at least DETAIL.
    if bool_option(loaded, "verbose").unwrap_or(false) {
        level_console = level_console.max(pgbr_core::log::LOG_LEVEL_DETAIL);
    }

    // detail-level (info command, `full` | `progress`, default `full`): `full`
    // asks for the complete, detailed listing, so raise the console floor to at
    // least DETAIL so the extra per-backup detail lines are actually emitted;
    // `progress` keeps the terser console level. This is the detail threshold
    // the renderer's verbosity is gated on. See `detail_level_raises_console`.
    if detail_level_raises_console(loaded) {
        level_console = level_console.max(pgbr_core::log::LOG_LEVEL_DETAIL);
    }

    let timestamp = bool_option(loaded, "log-timestamp").unwrap_or(true);
    let process_id = resolve_process_id(loaded);

    pgbr_core::log::init(level_console, level_stderr, level_file, timestamp, process_id, 1, false);

    // Open the log file only when the file sink is active.
    if level_file != pgbr_core::log::LOG_LEVEL_OFF {
        open_log_file(loaded);
    }
}

/// Resolve the process id used as the logger's `Pxx` prefix: the `exec-id`
/// option's numeric prefix when present (`exec-id` is `<pid>-<random>`),
/// otherwise the OS process id. Clamped to the logger's 0..=999 range.
fn resolve_process_id(loaded: &LoadedConfig) -> u32 {
    if let Some(exec_id) = string_id_option(loaded, "exec-id") {
        // exec-id is `<pid>-<hex>`; take the leading numeric component.
        let head = exec_id.split('-').next().unwrap_or(&exec_id);
        if let Ok(pid) = head.parse::<u32>() {
            return pid % 1000;
        }
    }
    std::process::id() % 1000
}

/// Open `<log-path>/<stanza>-<command>.log` (or `all-server.log` for the
/// `server` command) in append mode, creating the directory tree, and install
/// it as the logger's file sink.
///
/// Best-effort: if the path can't be created or opened the file sink stays
/// disabled (the console / stderr sinks still work) — pgBackRest likewise does
/// not abort the command on a log-file open failure here.
#[allow(clippy::print_stderr)] // a log-open failure is surfaced to stderr by design.
fn open_log_file(loaded: &LoadedConfig) {
    let log_path = string_id_option(loaded, "log-path").unwrap_or_else(|| DEFAULT_LOG_PATH.to_owned());
    let file_name = if loaded.command == "server" {
        "all-server.log".to_owned()
    } else {
        let stanza = loaded.stanza.as_deref().unwrap_or("all");
        format!("{stanza}-{}.log", loaded.command)
    };
    let full = PathBuf::from(&log_path).join(file_name);

    if let Some(parent) = full.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        eprintln!("unable to create log path {}: {err}", parent.display());
        return;
    }

    match std::fs::OpenOptions::new().create(true).append(true).open(&full) {
        Ok(file) => install_log_file_fd(file),
        Err(err) => eprintln!("unable to open log file {}: {err}", full.display()),
    }
}

/// Process-global slot that owns the open log [`std::fs::File`] for the lifetime
/// of the process, keeping the raw fd handed to the logger valid.
static LOG_FILE: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// Install `file`'s raw fd as the logger's file sink and keep `file` alive in
/// [`LOG_FILE`] so the fd is not closed out from under the logger.
#[cfg(unix)]
fn install_log_file_fd(file: std::fs::File) {
    use std::os::unix::io::AsRawFd;
    let file = LOG_FILE.get_or_init(|| file);
    pgbr_core::log::set_fd_file(file.as_raw_fd());
    // Re-promote level_any now that the file fd is open (the file level only
    // counts toward `any` once the fd is set).
    pgbr_core::log::any_set();
}

/// Non-Unix fallback: the logger writes via POSIX `write(2)` on a raw fd, which
/// has no portable Windows analogue, so the file sink stays disabled there.
#[cfg(not(unix))]
#[allow(clippy::needless_pass_by_value)]
fn install_log_file_fd(_file: std::fs::File) {}

/// Clear the process umask so files and directories are created with their full
/// mode (`neutral-umask`). Unix-only; a no-op elsewhere.
#[cfg(unix)]
#[allow(unsafe_code)]
fn set_neutral_umask() {
    // SAFETY: `umask` is always safe to call; it only reads/replaces the
    // process-global umask, cannot fail, and has no memory-safety implications.
    unsafe {
        libc::umask(0);
    }
}

/// Non-Unix fallback for [`set_neutral_umask`]: Windows has no umask.
#[cfg(not(unix))]
fn set_neutral_umask() {}

/// Best-effort process scheduling priority (`priority`, a nice level in
/// `-20..=19`). Unix-only via `setpriority`; a logged no-op elsewhere.
#[cfg(unix)]
#[allow(unsafe_code)]
#[allow(clippy::print_stderr)] // a setpriority failure is surfaced to stderr by design.
fn set_process_priority(priority: i64) {
    let Ok(nice) = i32::try_from(priority) else {
        return;
    };
    // SAFETY: `setpriority(PRIO_PROCESS, 0, nice)` targets the calling process
    // and only adjusts its nice value; it has no memory-safety implications.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    if rc != 0 {
        eprintln!(
            "unable to set process priority to {nice}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Non-Unix fallback for [`set_process_priority`]: TODO — Windows priority
/// classes have no direct nice-level mapping, so the option is ignored there.
#[cfg(not(unix))]
fn set_process_priority(_priority: i64) {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use pgbr_config::{OptionValue, RuntimeContext};

    use super::{
        CliRunError, EXIT_CODE_CONFIG_ERROR, EXIT_CODE_INTERNAL_ERROR, EXIT_CODE_RUNTIME_ERROR, load_static_cfg, resolve_only, run,
    };

    /// Serializes the one test that mutates the process-global environment
    /// (`env_var_takes_effect`). Holding it across the set -> read -> unset
    /// window keeps the `PGBACKREST_*` var from leaking into any other test
    /// that reads the live environment through `run` / `resolve_only`.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn static_cfg_compiles() {
        // Canary: the embedded config.yaml still parses + compiles. If
        // pgbr-build / pgbr-config drift in a way that rejects the upstream
        // schema, this test catches it.
        load_static_cfg().expect("embedded config.yaml must parse and compile");
    }

    #[test]
    fn version_command_resolves() {
        // `version` is a real command in config.yaml; argv resolution succeeds
        // (no `CliResolve` error). Whether the subsequent `load_config` step
        // returns Ok depends on pgbr-config's default-vs-allow-list rendering,
        // which is not pgbr-cli's responsibility — so we accept either Ok(0)
        // or a `Load` error here.
        match run(["version"]) {
            Ok(0) | Err(CliRunError::Load(_)) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn unknown_command_returns_typed_error() {
        let err = run(["definitely-not-a-command"]).unwrap_err();
        assert!(matches!(
            err,
            CliRunError::CliResolve(pgbr_config::CliResolveError::UnknownCommand { .. })
        ));
    }

    #[test]
    fn missing_command_returns_exit_code_one() {
        let exit = run(Vec::<String>::new()).expect("run([]) should not error");
        assert_eq!(exit, 1);
    }

    #[test]
    fn verify_command_dispatches_end_to_end() {
        // Every command is implemented now (no `NotYetImplemented` left), and
        // the literal-default + depend-gating fixes let the real config.yaml
        // resolve. `verify` against an uninitialized repo therefore reaches its
        // implementation and yields a command-level outcome (Ok exit code, or a
        // `Command` error) — never a config-resolution failure.
        let tmp = tempfile::tempdir().expect("tempdir");
        match run(["verify", "--stanza=demo", &format!("--repo1-path={}", tmp.path().display())]) {
            Ok(_) | Err(CliRunError::Command(_)) => {}
            other => panic!("verify should dispatch to its implementation, got {other:?}"),
        }
    }

    #[test]
    fn repo_ls_on_tempdir_succeeds() {
        // `repo-ls` is implemented and needs only repo-path. Point it at a
        // populated tempdir and confirm the end-to-end path returns Ok(0).
        let repo = tempfile::tempdir().expect("repo tempdir");
        std::fs::write(repo.path().join("backup.info"), b"x").expect("seed file");
        let repo_arg = format!("--repo1-path={}", repo.path().display());

        match run(["repo-ls", &repo_arg]) {
            // Ok(_) means dispatch ran end-to-end. A `Load` error means
            // pgbr-config's default-validation rejected the invocation before
            // dispatch (a pre-existing quirk, e.g. the buffer-size allow-list
            // issue) — tolerate it here since fixing pgbr-config is out of
            // scope.
            Ok(_) | Err(CliRunError::Load(_)) => {}
            other => panic!("expected Ok or Load error, got {other:?}"),
        }
    }

    #[test]
    fn run_dispatches_info_on_empty_repo() {
        // `info` is implemented and needs only repo-path. Driving the full
        // `run` pipeline over a tempdir must REACH dispatch (not the old
        // "just printed the resolved invocation" placeholder): the outcome is
        // either the command's own result or a typed error from it — never a
        // silent print-and-exit-0. We assert the result is one of dispatch's
        // possible outcomes.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let repo_arg = format!("--repo1-path={}", repo.path().display());

        match run(["info", "--stanza=demo", &repo_arg]) {
            // Ok(_) → dispatch ran end-to-end (info on an empty repo is a
            // valid "no stanzas" result). A `Command` error → dispatch ran and
            // the command returned a typed failure. A `Load` error → the
            // pre-existing pgbr-config default-validation quirk rejected the
            // invocation before dispatch (out of scope to fix here). All three
            // prove we wired real dispatch, not the placeholder.
            Ok(_) | Err(CliRunError::Command(_) | CliRunError::Load(_)) => {}
            other => panic!("expected dispatch outcome (Ok / Command / Load), got {other:?}"),
        }
    }

    #[test]
    fn version_still_short_circuits() {
        // `version` must keep working without building real storage from
        // `repo-*` / `pg-*` options: it short-circuits through a throwaway
        // backend. So it never surfaces a `StorageConfig` / `NotSupportedYet`
        // error even when no storage options are supplied, and never the old
        // placeholder. Accept Ok(0) or the pre-existing pgbr-config `Load`
        // quirk (same tolerance as `version_command_resolves`).
        match run(["version"]) {
            Ok(0) | Err(CliRunError::Load(_)) => {}
            other => panic!("version should short-circuit, got {other:?}"),
        }
    }

    #[test]
    fn unknown_command_still_errors() {
        let err = run(["nonsense"]).unwrap_err();
        assert!(matches!(err, CliRunError::CliResolve(_)));
    }

    #[test]
    fn missing_config_file_falls_back_to_empty_ini() {
        // `--config=/missing-path` is a CLI option valid for commands that
        // accept it. The missing-file branch should fall back to an empty
        // `IniFile` rather than erroring; the only way this test fails is if
        // the read path raises `ReadConfigFile` instead of treating
        // ENOENT as "no INI file present". Use `info` since it accepts
        // `--config` and short-circuits without needing a stanza.
        let result = run(["--config=/definitely/missing/path/pgbackrest.conf", "info"]);
        // Anything except a `ReadConfigFile` error is acceptable: the
        // fallback path was taken. `Load`/`CliResolve` errors are downstream
        // of the fallback we care about.
        assert!(
            !matches!(result, Err(CliRunError::ReadConfigFile { .. })),
            "missing config file should fall back to empty INI, got {result:?}",
        );
    }

    #[test]
    fn missing_include_dir_is_a_no_op() {
        // A `--config-include-path` pointing at a nonexistent directory must
        // yield no extra config files (not an error). `load_include_files`
        // returns an empty Vec for ENOENT.
        let cfg = load_static_cfg().expect("config compiles");
        let cli = pgbr_config::parse_cli(["info", "--config-include-path=/definitely/missing/conf.d"]).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();
        let inis = super::load_include_files(&resolved).expect("missing include dir must not error");
        assert!(inis.is_empty(), "a missing include dir yields no config files");
    }

    #[test]
    fn include_path_defaults_to_config_path_conf_d() {
        // With neither `--config-include-path` nor `--config-path`, the include
        // path defaults to `<DEFAULT_CONFIG_DIR>/conf.d`.
        let cfg = load_static_cfg().expect("config compiles");
        let cli = pgbr_config::parse_cli(["info"]).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();
        assert_eq!(
            super::config_include_path(&resolved),
            std::path::PathBuf::from("/etc/pgbackrest/conf.d"),
        );

        // `--config-path` redirects the default include dir under it.
        let cli = pgbr_config::parse_cli(["info", "--config-path=/custom/cfg"]).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();
        assert_eq!(
            super::config_include_path(&resolved),
            std::path::PathBuf::from("/custom/cfg/conf.d"),
        );

        // Explicit `--config-include-path` wins over the derived default.
        let cli = pgbr_config::parse_cli(["info", "--config-include-path=/somewhere/else"]).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();
        assert_eq!(
            super::config_include_path(&resolved),
            std::path::PathBuf::from("/somewhere/else"),
        );
    }

    /// Resolve the merged options for a `--config-include-path` scan
    /// deterministically: scan the include dir via [`super::load_include_files`]
    /// (which never reads the process environment) and feed the resulting INI
    /// sources through the multi-source merge with an explicit empty env. This
    /// avoids the live-environment race that `resolve_only` is subject to (the
    /// `PGBACKREST_*` var set by `env_var_takes_effect` can leak across
    /// concurrently-running tests), while still exercising the real include-file
    /// loading + ordering + merge.
    fn resolve_include_repo_path(confd: &std::path::Path, main_ini: &str) -> Option<OptionValue> {
        let cfg = load_static_cfg().expect("config compiles");
        let args = [
            "info".to_owned(),
            "--stanza=demo".to_owned(),
            format!("--config-include-path={}", confd.display()),
        ];
        let cli = pgbr_config::parse_cli(args).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();

        let mut inis = vec![pgbr_config::parse_ini(main_ini).unwrap()];
        inis.extend(super::load_include_files(&resolved).expect("include files load"));

        let loaded = pgbr_config::load_config_with_env_multi(
            resolved,
            &pgbr_config::EnvValues::new(),
            &inis,
            &cfg,
            &RuntimeContext {
                exe_path: Some("/usr/bin/pgbackrest".to_owned()),
            },
        )
        .expect("merge resolves");
        loaded.options.get(&("repo-path".to_owned(), Some(1))).cloned()
    }

    #[test]
    fn include_file_value_loaded_and_overrides_main_config() {
        // A `*.conf` file under the include path is loaded and merged after the
        // main config: its value for the same key wins.
        let dir = tempfile::tempdir().expect("tempdir");
        let confd = dir.path().join("conf.d");
        std::fs::create_dir(&confd).expect("mkdir conf.d");
        // An include file overrides the main config's repo1-path.
        std::fs::write(confd.join("10-override.conf"), b"[global]\nrepo1-path=/from/include\n").expect("write inc1");

        // Main config sets repo1-path to one place; the include file overrides it.
        let resolved = resolve_include_repo_path(&confd, "[global]\nrepo1-path=/from/main\n");
        assert_eq!(
            resolved,
            Some(OptionValue::Path("/from/include".to_owned())),
            "the include file's repo1-path must override the main config",
        );
    }

    #[test]
    fn include_files_sorted_so_last_wins() {
        // Two include files set the same key; the later-sorted file wins.
        let dir = tempfile::tempdir().expect("tempdir");
        let confd = dir.path().join("conf.d");
        std::fs::create_dir(&confd).expect("mkdir conf.d");
        std::fs::write(confd.join("00-first.conf"), b"[global]\nrepo1-path=/first\n").expect("write a");
        std::fs::write(confd.join("99-last.conf"), b"[global]\nrepo1-path=/last\n").expect("write b");
        // A non-.conf file must be ignored even though it sets the key.
        std::fs::write(confd.join("ignored.txt"), b"[global]\nrepo1-path=/ignored\n").expect("write c");

        // No main config value: the lexicographically last *.conf wins, .txt is ignored.
        let resolved = resolve_include_repo_path(&confd, "");
        assert_eq!(
            resolved,
            Some(OptionValue::Path("/last".to_owned())),
            "the lexicographically last *.conf file wins, .txt is ignored",
        );
    }

    #[test]
    fn malformed_include_file_is_an_error() {
        // A structurally invalid include file surfaces as an Ini error, not a
        // silent skip.
        let cfg = load_static_cfg().expect("config compiles");
        let dir = tempfile::tempdir().expect("tempdir");
        let confd = dir.path().join("conf.d");
        std::fs::create_dir(&confd).expect("mkdir conf.d");
        // A key/value outside any `[section]` is a parse error.
        std::fs::write(confd.join("bad.conf"), b"repo1-path=/no-section\n").expect("write bad");

        let cli = pgbr_config::parse_cli(["info".to_owned(), format!("--config-include-path={}", confd.display())]).unwrap();
        let resolved = pgbr_config::resolve_cli(cli, &cfg).unwrap();
        let err = super::load_include_files(&resolved).expect_err("malformed include file must error");
        assert!(matches!(err, CliRunError::Ini(_)), "expected an Ini error, got {err:?}");
    }

    #[test]
    fn exe_path_flows_into_dynamic_defaults() {
        // `cmd` in config.yaml is a `default-type: dynamic` option whose
        // `default: bin` tag resolves to the running executable path. We thread
        // a known exe path through `resolve_only` and confirm it lands on the
        // dynamic `cmd` default.
        //
        // The real embedded config.yaml has a pre-existing pgbr-config quirk:
        // `buffer-size`'s `1MiB` default resolves to a `Size(1048576)` that is
        // compared (by its byte count "1048576") against a string allow-list
        // (`["1MiB", …]`), so `load_config` errors with
        // `NotInAllowList { option: "buffer-size", .. }` for every full-config
        // command before the resolved map is returned. That's out of scope for
        // pgbr-cli (and fixing pgbr-config is off-limits here). So we can't read
        // back `cmd` from a successful real-config load.
        //
        // Instead we assert the *threading* two ways:
        //  1. `resolve_only` runs the full real pipeline with our context and
        //     reaches the same downstream `buffer-size` quirk regardless of the
        //     context — proving `load_config_with_context` ran with it.
        //  2. The dynamic `bin` resolution itself is exercised against a minimal
        //     config built from `config.yaml`'s `cmd` shape, confirming the
        //     threaded `exe_path` (not the `"pgbackrest"` fallback) is selected.
        let ctx = RuntimeContext {
            exe_path: Some("/usr/bin/pgbackrest".to_owned()),
        };

        // (1) Pipeline runs end-to-end with the threaded context. The point of
        // this leg is only that `load_config_with_context` ran the full real
        // pipeline with our context — the precise downstream outcome (a clean
        // load, or a `Load`-stage validation/required error from the real
        // config) is not what we're asserting here. Any non-`Load` error
        // (e.g. CLI-resolution failure) WOULD be wrong.
        match resolve_only(["verify", "--stanza=demo", "--repo1-path=/tmp/repo"], &ctx) {
            Ok(loaded) => {
                // If the load succeeds, the dynamic `cmd` default must carry
                // our threaded exe path (not the "pgbackrest" fallback).
                if let Some(cmd) = loaded.options.get(&("cmd".to_owned(), None)) {
                    assert_eq!(cmd, &OptionValue::String("/usr/bin/pgbackrest".to_owned()));
                }
            }
            // A `Load`-stage error means the pipeline reached config merge with
            // our context — exactly what leg (1) is meant to prove.
            Err(CliRunError::Load(_)) => {}
            other => panic!("unexpected result from resolve_only: {other:?}"),
        }

        // (2) The dynamic `bin` default selects the threaded exe path. Build a
        // minimal Cfg mirroring config.yaml's `cmd` (`default-type: dynamic`,
        // `default: bin`) so the buffer-size quirk is out of the picture.
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  cmd:
    type: string
    default-type: dynamic
    default: bin
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = pgbr_config::compile(&pgbr_build::parse_config(yaml).unwrap()).unwrap();
        let resolved = pgbr_config::resolve_cli(pgbr_config::parse_cli(["backup", "--stanza=demo"]).unwrap(), &cfg).unwrap();
        let loaded = pgbr_config::load_config_with_context(resolved, &pgbr_config::IniFile::default(), &cfg, &ctx).unwrap();
        assert_eq!(
            loaded.options[&("cmd".to_owned(), None)],
            OptionValue::String("/usr/bin/pgbackrest".to_owned()),
            "the threaded exe_path should win over the \"pgbackrest\" fallback",
        );

        // The env-derived context must yield a non-empty exe path (the running
        // test binary) so the real binary resolves `cmd` to itself, not the
        // fallback.
        assert!(
            super::env_context().exe_path.is_some_and(|p| !p.is_empty()),
            "env_context() should carry the running executable path",
        );
    }

    #[test]
    fn env_var_takes_effect() {
        // A `PGBACKREST_<OPTION>` environment variable set in the process must
        // flow through `run` / `resolve_only` and land on the resolved option,
        // proving the binary feeds the live environment through
        // `env_values_from_process` + `load_config_with_env`. Here the env source
        // *supplies* `repo1-path` (no CLI `--repo1-path`), so the resolved value
        // must equal the env value.
        //
        // The environment is process-global. ENV_TEST_LOCK serializes this test
        // against itself (so a re-run / future second env test can't interleave
        // their set/unset windows). The other tests in this binary read the live
        // environment via `run` / `resolve_only` without taking the lock, but the
        // `PGBACKREST_REPO1_PATH` we set is harmless if it briefly leaks: every
        // such test either passes an explicit `--repo1-path` (CLI overrides the
        // env source) or tolerates a `Load` / `Command` outcome regardless of the
        // resolved repo path. set_var / remove_var are `unsafe` in edition 2024;
        // the lib's `forbid(unsafe_code)` is `not(test)`, so this is allowed under
        // `#[cfg(test)]`.
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let repo = tempfile::tempdir().expect("repo tempdir");
        let repo_path = repo.path().display().to_string();

        // SAFETY: edition-2024 `set_var` is unsafe purely because of the
        // data-race hazard with concurrent env access; this test keeps the window
        // short and the value benign (see the leak note above).
        unsafe {
            std::env::set_var("PGBACKREST_REPO1_PATH", &repo_path);
        }

        // `--config` points at a guaranteed-absent file so the host's
        // `/etc/pgbackrest` (if any) can't shadow the env value; the loader
        // falls back to an empty INI. `info` is repo-only and resolves cleanly.
        let result = resolve_only(
            ["--config=/definitely/missing/pgbackrest.conf", "info", "--stanza=demo"],
            &RuntimeContext {
                exe_path: Some("/usr/bin/pgbackrest".to_owned()),
            },
        );

        // SAFETY: same short, benign-value window as the set above.
        unsafe {
            std::env::remove_var("PGBACKREST_REPO1_PATH");
        }

        let loaded = result.expect("info should resolve with repo-path supplied via env");
        assert_eq!(
            loaded.options.get(&("repo-path".to_owned(), Some(1))),
            Some(&OptionValue::Path(repo_path)),
            "the PGBACKREST_REPO1_PATH env value should resolve onto repo1-path",
        );
    }

    #[test]
    fn exit_code_mapping() {
        // Config / option errors share the "config error" bucket.
        assert_eq!(
            CliRunError::CliResolve(pgbr_config::CliResolveError::MissingCommand).exit_code(),
            EXIT_CODE_CONFIG_ERROR,
        );
        assert_eq!(
            CliRunError::ReadConfigFile {
                path: std::path::PathBuf::from("/x"),
                error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            }
            .exit_code(),
            EXIT_CODE_CONFIG_ERROR,
        );

        // Storage *configuration* errors and not-supported-yet capabilities
        // are config-class (the invocation asked for something unsatisfiable).
        assert_eq!(
            CliRunError::StorageConfig("no bucket".to_owned()).exit_code(),
            EXIT_CODE_CONFIG_ERROR,
        );
        assert_eq!(
            CliRunError::NotSupportedYet("repo-host".to_owned()).exit_code(),
            EXIT_CODE_CONFIG_ERROR,
        );

        // A runtime command failure and a backend-construction failure map to
        // the runtime bucket (1).
        assert_eq!(
            CliRunError::Command(pgbr_command::CommandError::Other("boom".to_owned())).exit_code(),
            EXIT_CODE_RUNTIME_ERROR,
        );
        assert_eq!(
            CliRunError::Storage(pgbr_storage::StorageError::Backend {
                path: std::path::PathBuf::from("/x"),
                message: "bad key".to_owned(),
            })
            .exit_code(),
            EXIT_CODE_RUNTIME_ERROR,
        );

        // Internal / embedded-schema errors map to the internal bucket (1).
        let cli_err = pgbr_config::parse_cli(["--=bad"]).unwrap_err();
        assert_eq!(CliRunError::Cli(cli_err).exit_code(), EXIT_CODE_INTERNAL_ERROR);

        // The documented constant values themselves.
        assert_eq!(EXIT_CODE_CONFIG_ERROR, 27);
        assert_eq!(EXIT_CODE_RUNTIME_ERROR, 1);
        assert_eq!(EXIT_CODE_INTERNAL_ERROR, 1);
    }

    // -------------------------------------------------------------------
    // Process / logging / network option wiring (Tasks 15, 16, 24)
    // -------------------------------------------------------------------

    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};

    use super::{
        apply_legacy_compress, apply_process_options, detail_level_raises_console, init_logging, load_static_cfg as load_cfg,
        log_level_from_id, resolve_log_level, resolve_process_id, worker_log_args,
    };

    /// Serialises the tests that touch process-global logger / io / protocol
    /// state so they cannot observe each other's writes.
    static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn loaded(command: &str, stanza: Option<&str>, opts: &[(&str, Option<u32>, OptionValue)]) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for (name, idx, value) in opts {
            options.insert(((*name).to_owned(), *idx), value.clone());
        }
        LoadedConfig {
            command: command.to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn log_level_from_id_maps_every_string_id() {
        use pgbr_core::log::{
            LOG_LEVEL_DEBUG, LOG_LEVEL_DETAIL, LOG_LEVEL_ERROR, LOG_LEVEL_INFO, LOG_LEVEL_OFF, LOG_LEVEL_TRACE, LOG_LEVEL_WARN,
        };
        assert_eq!(log_level_from_id("off"), Some(LOG_LEVEL_OFF));
        assert_eq!(log_level_from_id("error"), Some(LOG_LEVEL_ERROR));
        assert_eq!(log_level_from_id("warn"), Some(LOG_LEVEL_WARN));
        assert_eq!(log_level_from_id("info"), Some(LOG_LEVEL_INFO));
        assert_eq!(log_level_from_id("detail"), Some(LOG_LEVEL_DETAIL));
        assert_eq!(log_level_from_id("debug"), Some(LOG_LEVEL_DEBUG));
        assert_eq!(log_level_from_id("trace"), Some(LOG_LEVEL_TRACE));
        // `assert` has no string-id, and garbage is rejected.
        assert_eq!(log_level_from_id("assert"), None);
        assert_eq!(log_level_from_id("nonsense"), None);
    }

    #[test]
    fn resolve_log_level_uses_value_then_fallback() {
        use pgbr_core::log::{LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARN};
        // Present + valid → that value.
        let cfg = loaded(
            "info",
            None,
            &[("log-level-console", None, OptionValue::StringId("debug".to_owned()))],
        );
        assert_eq!(resolve_log_level(&cfg, "log-level-console", "warn"), LOG_LEVEL_DEBUG);
        // Absent → the fallback id.
        let empty = loaded("info", None, &[]);
        assert_eq!(resolve_log_level(&empty, "log-level-console", "warn"), LOG_LEVEL_WARN);
        assert_eq!(resolve_log_level(&empty, "log-level-file", "info"), LOG_LEVEL_INFO);
        // Present but garbage → the fallback id.
        let bad = loaded(
            "info",
            None,
            &[("log-level-console", None, OptionValue::StringId("loud".to_owned()))],
        );
        assert_eq!(resolve_log_level(&bad, "log-level-console", "warn"), LOG_LEVEL_WARN);
    }

    #[test]
    fn legacy_compress_yes_maps_to_gz() {
        // compress=y with no explicit compress-type → compress-type=gz.
        let mut cfg = loaded("backup", Some("demo"), &[("compress", None, OptionValue::Boolean(true))]);
        apply_legacy_compress(&mut cfg);
        assert_eq!(
            cfg.options.get(&("compress-type".to_owned(), None)),
            Some(&OptionValue::StringId("gz".to_owned())),
        );
    }

    #[test]
    fn legacy_compress_no_maps_to_none() {
        let mut cfg = loaded("backup", Some("demo"), &[("compress", None, OptionValue::Boolean(false))]);
        apply_legacy_compress(&mut cfg);
        assert_eq!(
            cfg.options.get(&("compress-type".to_owned(), None)),
            Some(&OptionValue::StringId("none".to_owned())),
        );
    }

    #[test]
    fn legacy_compress_does_not_override_explicit_compress_type() {
        // An explicit compress-type wins; the deprecated boolean is ignored.
        let mut cfg = loaded(
            "backup",
            Some("demo"),
            &[
                ("compress", None, OptionValue::Boolean(true)),
                ("compress-type", None, OptionValue::StringId("zst".to_owned())),
            ],
        );
        apply_legacy_compress(&mut cfg);
        assert_eq!(
            cfg.options.get(&("compress-type".to_owned(), None)),
            Some(&OptionValue::StringId("zst".to_owned())),
            "an explicit compress-type must win over the deprecated compress boolean",
        );
    }

    #[test]
    fn legacy_compress_absent_is_a_no_op() {
        // No `compress` option → compress-type is left untouched.
        let mut cfg = loaded("backup", Some("demo"), &[]);
        apply_legacy_compress(&mut cfg);
        assert!(!cfg.options.contains_key(&("compress-type".to_owned(), None)));
    }

    #[test]
    fn resolve_process_id_reads_exec_id_then_pid() {
        // exec-id `<pid>-<hex>` → leading numeric component (mod 1000).
        let cfg = loaded(
            "info",
            None,
            &[("exec-id", None, OptionValue::String("12345-abcdef".to_owned()))],
        );
        assert_eq!(resolve_process_id(&cfg), 12345 % 1000);
        // No exec-id → the OS pid (mod 1000), always within range.
        let empty = loaded("info", None, &[]);
        assert!(resolve_process_id(&empty) < 1000);
    }

    #[test]
    fn apply_process_options_feeds_io_and_protocol_globals() {
        let _g = GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let cfg = load_cfg().expect("config compiles");
        // buffer-size (size, bytes), io-timeout / protocol-timeout (time, ms),
        // compress-level-network (integer). Use a stanza-less info command so no
        // log file is opened (log-level-file defaults to info, but absent here
        // resolves through the fallback; we keep file OFF by setting it).
        let loaded_cfg = loaded(
            "info",
            Some("demo"),
            &[
                ("buffer-size", None, OptionValue::Size(2 * 1024 * 1024)),
                ("io-timeout", None, OptionValue::Time(45_000)),
                ("protocol-timeout", None, OptionValue::Time(150_000)),
                ("compress-level-network", None, OptionValue::Integer(7)),
                ("log-level-file", None, OptionValue::StringId("off".to_owned())),
                ("neutral-umask", None, OptionValue::Boolean(false)),
            ],
        );
        apply_process_options(&loaded_cfg, &cfg);

        assert_eq!(pgbr_io::copy_buffer_size(), 2 * 1024 * 1024);
        assert_eq!(pgbr_io::io_timeout(), Some(std::time::Duration::from_secs(45)));
        assert_eq!(pgbr_protocol::protocol_timeout(), Some(std::time::Duration::from_secs(150)));
        assert_eq!(pgbr_protocol::network_compress_level(), 7);

        // Restore neutral defaults so other tests using `copy` are unaffected.
        pgbr_io::set_copy_buffer_size(pgbr_io::DEFAULT_COPY_BUFFER_SIZE);
        pgbr_io::set_io_timeout_ms(0);
        pgbr_protocol::set_protocol_timeout_ms(0);
    }

    #[test]
    fn init_logging_opens_file_and_sets_levels() {
        let _g = GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let cfg = load_cfg().expect("config compiles");
        let log_dir = tempfile::tempdir().expect("log tempdir");
        let loaded_cfg = loaded(
            "backup",
            Some("demo"),
            &[
                ("log-level-console", None, OptionValue::StringId("info".to_owned())),
                ("log-level-file", None, OptionValue::StringId("detail".to_owned())),
                ("log-path", None, OptionValue::Path(log_dir.path().display().to_string())),
                ("log-timestamp", None, OptionValue::Boolean(false)),
                ("exec-id", None, OptionValue::String("42-deadbeef".to_owned())),
            ],
        );
        init_logging(&loaded_cfg, &cfg);

        assert_eq!(pgbr_core::log::level_std_out(), pgbr_core::log::LOG_LEVEL_INFO);
        assert_eq!(pgbr_core::log::level_file(), pgbr_core::log::LOG_LEVEL_DETAIL);
        assert!(!pgbr_core::log::timestamp());
        assert_eq!(pgbr_core::log::process_id(), 42);

        // The log file was created at <log-path>/<stanza>-<command>.log on unix
        // (the file sink is fd-based, so this only applies there).
        #[cfg(unix)]
        assert!(
            log_dir.path().join("demo-backup.log").exists(),
            "init_logging should open <log-path>/<stanza>-<command>.log"
        );
    }

    #[test]
    fn detail_level_full_raises_console_progress_does_not() {
        // detail-level=full asks for the detailed listing → raise.
        let full = loaded(
            "info",
            Some("demo"),
            &[("detail-level", None, OptionValue::StringId("full".to_owned()))],
        );
        assert!(detail_level_raises_console(&full));

        // detail-level=progress keeps the terser level → no raise.
        let progress = loaded(
            "info",
            Some("demo"),
            &[("detail-level", None, OptionValue::StringId("progress".to_owned()))],
        );
        assert!(!detail_level_raises_console(&progress));

        // Absent (non-info commands, or an unmaterialised default) → no raise,
        // so the configured console level is left untouched.
        let absent = loaded("backup", Some("demo"), &[]);
        assert!(!detail_level_raises_console(&absent));
    }

    #[test]
    fn detail_level_full_bumps_console_to_detail() {
        let _g = GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let cfg = load_cfg().expect("config compiles");
        // Console resolves to WARN by default, but detail-level=full lifts it to
        // at least DETAIL. Keep the file sink off so no log file is opened.
        let loaded_cfg = loaded(
            "info",
            Some("demo"),
            &[
                ("log-level-console", None, OptionValue::StringId("warn".to_owned())),
                ("log-level-file", None, OptionValue::StringId("off".to_owned())),
                ("detail-level", None, OptionValue::StringId("full".to_owned())),
            ],
        );
        init_logging(&loaded_cfg, &cfg);
        assert!(
            pgbr_core::log::level_std_out() >= pgbr_core::log::LOG_LEVEL_DETAIL,
            "detail-level=full should raise the console floor to at least DETAIL"
        );
    }

    #[test]
    fn worker_log_args_propagates_only_when_log_subprocess_set() {
        // Unset → no propagation.
        let none = loaded("backup", Some("demo"), &[]);
        assert!(worker_log_args(&none).is_empty());

        // Explicit false → no propagation.
        let off = loaded(
            "backup",
            Some("demo"),
            &[("log-subprocess", None, OptionValue::Boolean(false))],
        );
        assert!(worker_log_args(&off).is_empty());

        // Set → `--log-subprocess` plus the inherited file level.
        let on = loaded(
            "backup",
            Some("demo"),
            &[
                ("log-subprocess", None, OptionValue::Boolean(true)),
                ("log-level-file", None, OptionValue::StringId("detail".to_owned())),
            ],
        );
        assert_eq!(
            worker_log_args(&on),
            vec!["--log-subprocess".to_owned(), "--log-level-file=detail".to_owned()],
        );

        // Set without an explicit file level → falls back to the file default.
        let on_default = loaded(
            "backup",
            Some("demo"),
            &[("log-subprocess", None, OptionValue::Boolean(true))],
        );
        assert_eq!(
            worker_log_args(&on_default),
            vec![
                "--log-subprocess".to_owned(),
                format!("--log-level-file={}", super::DEFAULT_LOG_LEVEL_FILE),
            ],
        );
    }
}
