//! Top-level entry point for the `pgbackrest` Rust binary.
//!
//! Wires `pgbr_build` (config schema), `pgbr_config` (CLI/INI/merge),
//! and (eventually) `pgbr_command` (per-command implementations) into one
//! invocation. This slice ships the parse + resolve + load pipeline plus a
//! human-readable dump of the resolved invocation; per-command dispatch is
//! intentionally a placeholder.

#![cfg_attr(not(test), forbid(unsafe_code))]

use std::path::PathBuf;

use pgbr_config::{
    Cfg, CliResolveError, CompileError, IniFile, LoadError, LoadedConfig, OptionValue, ResolvedCli, compile, load_config,
    parse_cli, parse_ini, resolve_cli,
};

/// Hard-coded copy of `src/build/config/config.yaml`. Embeds the schema at
/// compile time so the binary does not have to ship the YAML file alongside
/// itself. Updated whenever the upstream `config.yaml` changes (re-run
/// `cargo build` to pick up a new copy).
const CONFIG_YAML: &str = include_str!("../../../src/build/config/config.yaml");

/// Default path to `pgbackrest.conf` if `--config` is not supplied.
const DEFAULT_CONFIG_PATH: &str = "/etc/pgbackrest/pgbackrest.conf";

/// Top-level errors. The exit code reflects the error category (matches the
/// rough shape of pgBackRest's C error codes — exact alignment is a future
/// commit).
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
        }
    }
}

impl std::error::Error for CliRunError {}

/// Run the CLI end-to-end.
///
/// `args` is the argv excluding `argv[0]` (the program name). Returns the
/// process exit code (0 = success, non-zero = error).
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
#[allow(clippy::print_stdout, clippy::print_stderr)] // CLI binary writes to stdout/stderr by design.
pub fn run<I, S>(args: I) -> Result<i32, CliRunError>
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

    // Determine the config file path. `--config=<path>` lives in
    // `resolved.options[("config", None)]`. Fall back to the default.
    let config_path = config_file_path(&resolved);

    let ini = match std::fs::read_to_string(&config_path) {
        Ok(text) => parse_ini(&text).map_err(CliRunError::Ini)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => IniFile::default(),
        Err(error) => {
            return Err(CliRunError::ReadConfigFile {
                path: config_path,
                error,
            });
        }
    };

    let loaded = load_config(resolved, &ini, &cfg).map_err(CliRunError::Load)?;
    print_resolved_invocation(&loaded);

    // Per-command dispatch is a placeholder; `pgbr-command` lands in a
    // separate commit. For now we report success once the parse/resolve/load
    // pipeline succeeds.
    Ok(0)
}

fn load_static_cfg() -> Result<Cfg, CliRunError> {
    let parsed = pgbr_build::parse_config(CONFIG_YAML).map_err(CliRunError::ConfigYaml)?;
    compile(&parsed).map_err(CliRunError::Compile)
}

fn config_file_path(resolved: &ResolvedCli) -> PathBuf {
    match resolved.options.get(&("config".to_owned(), None)) {
        Some(OptionValue::Path(p) | OptionValue::String(p)) => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_CONFIG_PATH),
    }
}

#[allow(clippy::print_stdout)] // CLI binary writes to stdout by design.
fn print_resolved_invocation(loaded: &LoadedConfig) {
    println!("command:      {}", loaded.command);
    println!("command-role: {}", loaded.command_role.as_str());
    if let Some(stanza) = &loaded.stanza {
        println!("stanza:       {stanza}");
    }
    if !loaded.params.is_empty() {
        println!("params:       {}", loaded.params.join(" "));
    }
    println!("options:");
    for ((name, group), value) in &loaded.options {
        let key = group.as_ref().map_or_else(|| name.clone(), |idx| format!("{name}[{idx}]"));
        println!("  {key} = {}", format_value(value));
    }
}

fn format_value(value: &OptionValue) -> String {
    match value {
        OptionValue::Boolean(b) => b.to_string(),
        OptionValue::Integer(n) => n.to_string(),
        OptionValue::Size(n) => format!("{n} (bytes)"),
        OptionValue::Time(n) => format!("{n} (seconds)"),
        OptionValue::Path(s) | OptionValue::String(s) | OptionValue::StringId(s) => s.clone(),
        OptionValue::List(items) => format!("[{}]", items.join(", ")),
        OptionValue::Hash(map) => {
            let pairs: Vec<String> = map.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{{{}}}", pairs.join(", "))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{CliRunError, load_static_cfg, run};

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
}
