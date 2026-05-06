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
}
