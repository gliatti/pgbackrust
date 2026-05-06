//! Enums shared by the runtime config model.
//!
//! These types correspond to the C enums in `src/config/config.h`
//! (`ConfigCommandRole`, `LockType`).

/// Command role: `main` is the user-facing process; `async`, `local`, and
/// `remote` are subordinate processes the main role can spawn.
///
/// Mirrors `ConfigCommandRole` from `src/config/config.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigCommandRole {
    /// Called directly by the user; main process of a command.
    Main,
    /// Async worker; runs in the background while the main process returns.
    Async,
    /// Local worker for parallelizing jobs.
    Local,
    /// Remote worker for accessing resources on another host.
    Remote,
}

impl ConfigCommandRole {
    /// Lower-case spelling that appears in the YAML and in the wire protocol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Async => "async",
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    /// Parse the lower-case role name from `config.yaml` / wire protocol.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "main" => Some(Self::Main),
            "async" => Some(Self::Async),
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

/// Option value type as declared by `type:` in `config.yaml`.
///
/// Mirrors the `OptionType` C enum (one of `string`, `path`, `boolean`,
/// `integer`, `size`, `time`, `string-id`, `list`, `hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionType {
    Boolean,
    Integer,
    Size,
    Time,
    Path,
    String,
    StringId,
    List,
    Hash,
}

impl OptionType {
    /// Parse the lower-case spelling used in `config.yaml`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "boolean" => Some(Self::Boolean),
            "integer" => Some(Self::Integer),
            "size" => Some(Self::Size),
            "time" => Some(Self::Time),
            "path" => Some(Self::Path),
            "string" => Some(Self::String),
            "string-id" => Some(Self::StringId),
            "list" => Some(Self::List),
            "hash" => Some(Self::Hash),
            _ => None,
        }
    }

    /// Lower-case spelling used in `config.yaml` and in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Size => "size",
            Self::Time => "time",
            Self::Path => "path",
            Self::String => "string",
            Self::StringId => "string-id",
            Self::List => "list",
            Self::Hash => "hash",
        }
    }
}

/// Configuration-file section the option lives in.
///
/// Command-line-only options omit `section:` entirely; the value is `None`
/// in that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionSection {
    /// `[global]` section — shared across stanzas.
    Global,
    /// `[<stanza>]` section — per-stanza override.
    Stanza,
}

impl OptionSection {
    /// Parse the lower-case spelling used in `config.yaml`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "global" => Some(Self::Global),
            "stanza" => Some(Self::Stanza),
            _ => None,
        }
    }

    /// Lower-case spelling used in `config.yaml` and in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Stanza => "stanza",
        }
    }
}

/// How `default:` should be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefaultType {
    /// Emit the default literal as-is (used to embed C-define references).
    Literal,
    /// Default is computed at runtime from a recognised tag (`bin` =>
    /// `argv[0]`).
    Dynamic,
    /// Default is a string that should be quoted in generated C.
    Quote,
}

impl DefaultType {
    /// Parse the lower-case spelling used in `config.yaml`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "literal" => Some(Self::Literal),
            "dynamic" => Some(Self::Dynamic),
            "quote" => Some(Self::Quote),
            _ => None,
        }
    }

    /// Lower-case spelling used in `config.yaml` and in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Dynamic => "dynamic",
            Self::Quote => "quote",
        }
    }
}

/// Indexed group an option belongs to (`pg`, `repo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionGroup {
    /// `pgN-*` group (e.g. `pg1-path`, `pg2-host`).
    Pg,
    /// `repoN-*` group.
    Repo,
}

impl OptionGroup {
    /// Parse the lower-case spelling used in `config.yaml`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pg" => Some(Self::Pg),
            "repo" => Some(Self::Repo),
            _ => None,
        }
    }

    /// Lower-case spelling used in `config.yaml` and in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pg => "pg",
            Self::Repo => "repo",
        }
    }
}

/// Lock category required by a command.
///
/// Mirrors `LockType` from `src/config/config.h`. `LockType::None` is the
/// default when a command does not declare a `lock-type:` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LockType {
    Archive,
    Backup,
    Restore,
    All,
    #[default]
    None,
}

impl LockType {
    /// Lower-case spelling used in `config.yaml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::All => "all",
            Self::None => "none",
        }
    }

    /// Parse a `lock-type:` value from `config.yaml`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "archive" => Some(Self::Archive),
            "backup" => Some(Self::Backup),
            "restore" => Some(Self::Restore),
            "all" => Some(Self::All),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trip() {
        for role in [
            ConfigCommandRole::Main,
            ConfigCommandRole::Async,
            ConfigCommandRole::Local,
            ConfigCommandRole::Remote,
        ] {
            assert_eq!(ConfigCommandRole::parse(role.as_str()), Some(role));
        }
        assert_eq!(ConfigCommandRole::parse("not-a-role"), None);
    }

    #[test]
    fn lock_type_round_trip() {
        for lt in [
            LockType::Archive,
            LockType::Backup,
            LockType::Restore,
            LockType::All,
            LockType::None,
        ] {
            assert_eq!(LockType::parse(lt.as_str()), Some(lt));
        }
        assert_eq!(LockType::parse("nonsense"), None);
    }

    #[test]
    fn lock_type_default_is_none() {
        assert_eq!(LockType::default(), LockType::None);
    }

    #[test]
    fn option_type_round_trip() {
        for ty in [
            OptionType::Boolean,
            OptionType::Integer,
            OptionType::Size,
            OptionType::Time,
            OptionType::Path,
            OptionType::String,
            OptionType::StringId,
            OptionType::List,
            OptionType::Hash,
        ] {
            assert_eq!(OptionType::parse(ty.as_str()), Some(ty));
        }
        assert_eq!(OptionType::parse("oops"), None);
    }

    #[test]
    fn option_section_round_trip() {
        for s in [OptionSection::Global, OptionSection::Stanza] {
            assert_eq!(OptionSection::parse(s.as_str()), Some(s));
        }
        assert_eq!(OptionSection::parse("oops"), None);
    }

    #[test]
    fn default_type_round_trip() {
        for d in [DefaultType::Literal, DefaultType::Dynamic, DefaultType::Quote] {
            assert_eq!(DefaultType::parse(d.as_str()), Some(d));
        }
        assert_eq!(DefaultType::parse("oops"), None);
    }

    #[test]
    fn option_group_round_trip() {
        for g in [OptionGroup::Pg, OptionGroup::Repo] {
            assert_eq!(OptionGroup::parse(g.as_str()), Some(g));
        }
        assert_eq!(OptionGroup::parse("oops"), None);
    }
}
