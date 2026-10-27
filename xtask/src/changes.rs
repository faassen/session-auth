use anyhow::{Result, bail};
use jiff::civil::Date;
use semver::Version;

const UNRELEASED: &str = "## Unreleased";
const SECTION_PREFIX: &str = "## ";

/// The text of CHANGES.md, written by hand, with the changes of the next
/// release under an `## Unreleased` heading.
pub struct Changes {
    text: String,
}

impl Changes {
    pub fn new(text: String) -> Self {
        Self { text }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Turn the `## Unreleased` heading into the heading of the release of the
    /// version on the date.
    pub fn release(&self, version: &Version, date: Date) -> Result<Changes> {
        let lines: Vec<&str> = self.text.lines().collect();
        let Some(index) = lines.iter().position(|line| line.trim_end() == UNRELEASED) else {
            bail!("CHANGES.md has no `{UNRELEASED}` heading");
        };
        let has_changes = lines[index + 1..]
            .iter()
            .take_while(|line| !line.starts_with(SECTION_PREFIX))
            .any(|line| !line.trim().is_empty());
        if !has_changes {
            bail!("CHANGES.md lists no changes under `{UNRELEASED}`");
        }
        let heading = format!("{SECTION_PREFIX}{version} ({date})");
        let mut released = lines;
        released[index] = &heading;
        Ok(Changes::new(released.join("\n") + "\n"))
    }

    /// Add an empty `## Unreleased` heading above the latest release.
    pub fn with_unreleased(&self) -> Changes {
        let text = if let Some(index) = self.text.find(&format!("\n{SECTION_PREFIX}")) {
            let (before, after) = self.text.split_at(index + 1);
            format!("{before}{UNRELEASED}\n\n{after}")
        } else {
            format!("{}\n{UNRELEASED}\n", self.text)
        };
        Changes::new(text)
    }
}

#[cfg(test)]
mod tests {
    use jiff::civil::date;

    use super::*;

    const CHANGES: &str = "# Changes\n\n## Unreleased\n\n- New thing.\n\n## 0.1.0 (2026-01-01)\n\n- Initial release.\n";

    #[test]
    fn release_stamps_version_and_date() {
        let changes = Changes::new(CHANGES.to_string());
        let released = changes
            .release(&Version::new(0, 2, 0), date(2026, 10, 27))
            .unwrap();
        assert_eq!(
            released.text(),
            "# Changes\n\n## 0.2.0 (2026-10-27)\n\n- New thing.\n\n## 0.1.0 (2026-01-01)\n\n- Initial release.\n"
        );
    }

    #[test]
    fn release_without_unreleased_heading_fails() {
        let changes = Changes::new("# Changes\n\n## 0.1.0 (2026-01-01)\n".to_string());
        assert!(
            changes
                .release(&Version::new(0, 2, 0), date(2026, 10, 27))
                .is_err()
        );
    }

    #[test]
    fn release_without_changes_fails() {
        let changes =
            Changes::new("# Changes\n\n## Unreleased\n\n## 0.1.0 (2026-01-01)\n".to_string());
        assert!(
            changes
                .release(&Version::new(0, 2, 0), date(2026, 10, 27))
                .is_err()
        );
    }

    #[test]
    fn with_unreleased_adds_heading_above_latest_release() {
        let changes =
            Changes::new("# Changes\n\n## 0.2.0 (2026-10-27)\n\n- New thing.\n".to_string());
        assert_eq!(
            changes.with_unreleased().text(),
            "# Changes\n\n## Unreleased\n\n## 0.2.0 (2026-10-27)\n\n- New thing.\n"
        );
    }
}
