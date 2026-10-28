mod changes;
mod level;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jiff::Zoned;
use semver::Version;
use toml_edit::{DocumentMut, value};

use changes::Changes;
use level::Level;

const PACKAGE: &str = "session-auth";
const BOOKMARK: &str = "main";
const CARGO_TOML: &str = "Cargo.toml";
const CHANGES_MD: &str = "CHANGES.md";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Subcommand)]
enum XtaskCommand {
    /// Release the next version: bump Cargo.toml, stamp CHANGES.md, publish to
    /// crates.io, commit and tag with jj, and push to GitHub.
    Release {
        /// The level of the release. Leave it out for the first release, to
        /// release the current version.
        level: Option<Level>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask is not in a workspace")?
        .to_path_buf();
    let workspace = Workspace { root };
    match cli.command {
        XtaskCommand::Release { level } => workspace.release(level),
    }
}

struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn release(&self, level: Option<Level>) -> Result<()> {
        if !self
            .output("jj", &["diff", "--name-only"])?
            .trim()
            .is_empty()
        {
            bail!("the working copy has changes; commit them first");
        }

        let cargo_toml_path = self.root.join(CARGO_TOML);
        let mut cargo_toml: DocumentMut = fs::read_to_string(&cargo_toml_path)?.parse()?;
        let current = cargo_toml["package"]["version"]
            .as_str()
            .context("Cargo.toml has no package version")?
            .parse::<Version>()?;

        let changes_path = self.root.join(CHANGES_MD);
        let changes = Changes::new(fs::read_to_string(&changes_path)?);
        let version = if let Some(level) = level {
            level.bump(&current)
        } else {
            if changes.has_releases() {
                bail!("give the level of the release: major, minor or patch");
            }
            current
        };
        let version = &version;
        let released = changes.release(version, Zoned::now().date())?;

        cargo_toml["package"]["version"] = value(version.to_string());
        fs::write(&cargo_toml_path, cargo_toml.to_string())?;
        fs::write(&changes_path, released.text())?;
        self.run("cargo", &["update", "--workspace"])?;

        // Verify the package before anything is committed. The working copy
        // was clean, so restoring it undoes only the release's own changes.
        if let Err(error) = self.run(
            "cargo",
            &[
                "publish",
                "--package",
                PACKAGE,
                "--dry-run",
                "--allow-dirty",
            ],
        ) {
            self.run("jj", &["restore"])?;
            return Err(error.context("the dry run failed; the version bump was undone"));
        }

        let tag = format!("v{version}");
        self.run(
            "jj",
            &["commit", "--message", &format!("Release {version}.")],
        )?;
        self.run("cargo", &["publish", "--package", PACKAGE, "--no-verify"])
            .context("publishing failed after the release commit was made")?;
        self.run("jj", &["tag", "set", &tag, "--revision", "@-"])?;
        self.run("jj", &["bookmark", "set", BOOKMARK, "--revision", "@-"])?;
        self.run(
            "jj",
            &["git", "push", "--bookmark", BOOKMARK, "--tag", &tag],
        )?;

        fs::write(&changes_path, released.with_unreleased().text())?;
        println!("Released {version}. CHANGES.md has a new `## Unreleased` heading.");
        Ok(())
    }

    fn command(&self, program: &str, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args).current_dir(&self.root);
        command
    }

    fn run(&self, program: &str, args: &[&str]) -> Result<()> {
        let status = self
            .command(program, args)
            .status()
            .with_context(|| format!("could not run {program}"))?;
        if !status.success() {
            bail!("`{program} {}` failed", args.join(" "));
        }
        Ok(())
    }

    fn output(&self, program: &str, args: &[&str]) -> Result<String> {
        let output = self
            .command(program, args)
            .output()
            .with_context(|| format!("could not run {program}"))?;
        if !output.status.success() {
            bail!("`{program} {}` failed", args.join(" "));
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}
