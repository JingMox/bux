//! `bux volume` — named volume management.

use anyhow::{Context, Result};
use clap::Subcommand;

use crate::OutputFormat;
use crate::vm::open_runtime;

/// Subcommands for `bux volume`.
#[derive(Subcommand)]
pub enum VolumeAction {
    /// Create a named volume.
    Create {
        /// Volume name (`[A-Za-z0-9._-]`).
        name: String,
    },
    /// List named volumes.
    #[command(visible_alias = "ls")]
    List {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Remove a named volume (fails if still attached to a VM).
    Rm {
        /// Volume name.
        name: String,
    },
}

pub fn dispatch(action: VolumeAction) -> Result<()> {
    match action {
        VolumeAction::Create { name } => create(&name),
        VolumeAction::List { format } => list(format),
        VolumeAction::Rm { name } => rm(&name),
    }
}

fn create(name: &str) -> Result<()> {
    let rt = open_runtime()?;
    let info = rt.volumes().create(name).context("create volume")?;
    println!("{}", info.name);
    Ok(())
}

fn list(format: OutputFormat) -> Result<()> {
    let rt = open_runtime()?;
    let vols = rt.volumes().list().context("list volumes")?;

    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&vols)?);
        return Ok(());
    }

    if vols.is_empty() {
        println!("No volumes.");
        return Ok(());
    }
    println!("{:<24} PATH", "NAME");
    for v in &vols {
        println!("{:<24} {}", v.name, v.path.display());
    }
    Ok(())
}

fn rm(name: &str) -> Result<()> {
    let rt = open_runtime()?;
    rt.volumes().remove(name).context("remove volume")?;
    println!("{name}");
    Ok(())
}
