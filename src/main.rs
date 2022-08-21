use std::path::PathBuf;
use std::result::Result::Ok;

use anyhow::*;
use linemux::{Line, MuxedLines};

mod clf;
mod sshd;
mod utils;

mod jail;
use crate::jail::Jail;
use crate::utils::*;

async fn run() -> Result<()> {
    let args = utils::cli().get_matches();
    let mut ml = MuxedLines::new()?;

    // jail
    let jailtime_str = args.value_of("jailtime").unwrap_or("");
    let jailtime = jailtime_str.parse().context("parsing jailtime")?;

    let allowance_str = args.value_of("allowance").unwrap_or("");
    let allowance = allowance_str.parse().context("parsing allowance")?;

    let jail = Jail::new(allowance, jailtime)?;

    // sshd
    let mut path_sshd: PathBuf = args.value_of("sshd_logpath").unwrap_or("").into();
    if path_sshd.exists() {
        path_sshd = std::fs::canonicalize(path_sshd)?;
        ml.add_file(&path_sshd).await?;
        log!("starting with sshd parsing at {:?}", &path_sshd);
    }

    // common log format
    let mut path_clf: PathBuf = args.value_of("clf_logpath").unwrap_or("").into();
    if path_clf.exists() {
        path_clf = std::fs::canonicalize(path_clf)?;
        ml.add_file(&path_clf).await?;
        log!("starting with clf parsing at {:?}", &path_clf);
    }

    let assess_line = |line: Line| {
        let payload = line.line();
        let path = line.source();

        let (target, ret) = if path == path_sshd {
            ("sshd", sshd::parse(payload)?)
        } else if path == path_clf {
            ("clf", clf::parse(payload)?)
        } else {
            bail!("file {:?} unknown", path)
        };

        if let ParsingStatus::BadEntry(ip) = ret {
            jail.sentence(ip, target)?;
        }

        Ok(())
    };

    while let Ok(Some(line)) = ml.next_line().await {
        if let Err(e) = assess_line(line) {
            log!("ERR: {:?}", e);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await?;
    eprintln!("\n");
    let _ = utils::cli().print_help();
    Ok(())
}
