//! `pgbackrest` binary entry point. Forwards argv (sans program name) to
//! `pgbr_cli::run` and exits with the returned status code. Diagnostics
//! are printed to stderr by the run path; this entry point only translates
//! errors into exit codes.

#![cfg_attr(not(test), forbid(unsafe_code))]

#[allow(clippy::print_stderr)] // CLI binary writes to stderr by design.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit = match pgbr_cli::run(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("pgbackrest: {err}");
            1
        }
    };
    std::process::exit(exit);
}
