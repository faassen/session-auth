use clap::ValueEnum;
use semver::Version;

/// The level of a release, which says which part of the version to bump.
#[derive(Clone, Copy, ValueEnum)]
pub enum Level {
    /// Breaking changes.
    Major,
    /// New features.
    Minor,
    /// Bug fixes.
    Patch,
}

impl Level {
    pub fn bump(self, version: &Version) -> Version {
        match self {
            Level::Major => Version::new(version.major + 1, 0, 0),
            Level::Minor => Version::new(version.major, version.minor + 1, 0),
            Level::Patch => Version::new(version.major, version.minor, version.patch + 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_major() {
        assert_eq!(
            Level::Major.bump(&Version::new(0, 2, 3)),
            Version::new(1, 0, 0)
        );
    }

    #[test]
    fn bump_minor() {
        assert_eq!(
            Level::Minor.bump(&Version::new(0, 2, 3)),
            Version::new(0, 3, 0)
        );
    }

    #[test]
    fn bump_patch() {
        assert_eq!(
            Level::Patch.bump(&Version::new(0, 2, 3)),
            Version::new(0, 2, 4)
        );
    }
}
