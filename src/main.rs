use std::result::Result::Ok;

use anyhow::*;
use clap::Parser;
use linemux::{Line, MuxedLines};

mod clf;
mod generic;
mod json;
mod sshd;
mod utils;

mod jail;
use crate::jail::Jail;
use crate::utils::*;

async fn run() -> Result<()> {
    let args = utils::Args::parse();
    let mut ml = MuxedLines::new()?;

    // HTTP statuses
    let ok_statuses = args.valid_http_statuses.clone();
    let ok_statuses_parsed = parse_statuses(&ok_statuses)?;
    let ok_statuses_ref = ok_statuses_parsed.as_ref();

    // generic parser
    let generic_path = args.generic_logpath.as_ref();
    let generic_ip_re = args.generic_ip.as_ref();
    let generic_positive = args.generic_positive.as_ref();
    let generic_negative = args.generic_negative.as_ref();
    if args.generic_ip.is_some()
        || args.generic_logpath.is_some()
        || args.generic_positive.is_some()
        || args.generic_negative.is_some()
    {
        if args.generic_ip.is_none() || args.generic_logpath.is_none() {
            bail!("generic parser needs both ip regex and log file path");
        }
        if !(args.generic_positive.is_some() ^ args.generic_negative.is_some()) {
            bail!("generic parser requires either a positive or a negative regex");
        }
        if let Some(p) = generic_path.as_ref() {
            ml.add_file(&p).await?;
            log!("starting with generic parsing at {:?}", &p);
        }
    }

    // sshd
    let sshd_logpath = args.sshd_logpath.as_ref();
    if let Some(p) = sshd_logpath {
        ml.add_file(&p).await?;
        log!("starting with sshd parsing at {:?}", &p);
    }

    // common log format
    let clf_logpath = args.clf_logpath.as_ref();
    if let Some(p) = clf_logpath {
        ml.add_file(&p).await?;
        log!("starting with clf parsing at {:?}", &p);
    }

    // json
    let json_logpath = args.json_logpath.as_ref();
    if let Some(p) = json_logpath {
        ml.add_file(&p).await?;
        log!("starting with json parsing at {:?}", &p);
    }

    if json_logpath.is_none() && clf_logpath.is_none() && sshd_logpath.is_none() {
        bail!("no log files to parse, see --help");
    }

    // jail
    let jail = Jail::new(args.allowance, args.jailtime)?;

    let assess_line = |line: Line| {
        let payload = line.line();
        let path_buf = Some(line.source().to_path_buf());
        let path = path_buf.as_ref();

        let (target, ret) = if path == sshd_logpath {
            ("sshd", sshd::parse(payload)?)
        } else if path == clf_logpath {
            ("clf", clf::parse(payload, ok_statuses_ref)?)
        } else if path == json_logpath {
            ("json", json::parse(payload, ok_statuses_ref)?)
        } else if path == generic_path {
            (
                "generic",
                generic::parse(payload, generic_ip_re, generic_positive, generic_negative)?,
            )
        } else {
            bail!("file {:?} unknown ?", path)
        };

        if let ParsingStatus::BadEntry(ip) = ret {
            if args.verbose {
                log!("{} logged offence for {}", target, ip);
            }
            let banned = jail.sentence(ip)?;
            if banned {
                log!("{} jailtime for {}", target, ip);
            }
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
    Ok(())
}
