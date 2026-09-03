use std::result::Result::Ok;

use anyhow::*;
use clap::Parser;
use linemux::{Line, MuxedLines};

mod caddy;
mod clf;
mod generic;
mod probes;
mod utils;

mod jail;
use crate::jail::Jail;
use crate::utils::*;

async fn run() -> Result<()> {
    let args = utils::Args::parse();
    let mut ml = MuxedLines::new()?;

    // HTTP statuses - opt-in, on top of the probe detection
    let invalid_statuses_parsed = match &args.invalid_http_statuses {
        Some(s) => parse_statuses(s)?,
        None => vec![],
    };
    let invalid_statuses_ref: &[u32] = invalid_statuses_parsed.as_ref();

    // probes - loaded from --probelist if given, built-in list otherwise
    let probelist = match args.probelist.as_ref() {
        Some(p) => {
            let pl = probes::ProbeList::load(p)?;
            log!("loaded {} probes from {:?}", pl.len(), p);
            pl
        }
        None => probes::ProbeList::builtin(),
    };
    let probelist = &probelist;

    // generic parser
    let generic_paths = &args.generic_logpath;
    let generic_ip_re = args.generic_ip.as_ref();
    let generic_positive = args.generic_positive.as_ref();
    let generic_negative = args.generic_negative.as_ref();
    for p in generic_paths {
        ml.add_file(&p).await?;
        log!("starting with generic parsing at {:?}", &p);
    }

    // common log format
    let clf_logpaths = &args.clf_logpath;
    for p in clf_logpaths {
        ml.add_file(&p).await?;
        log!("starting with clf parsing at {:?}", &p);
    }

    // caddy json
    let caddy_logpaths = &args.caddy_logpath;
    for p in caddy_logpaths {
        ml.add_file(&p).await?;
        log!("starting with caddy parsing at {:?}", &p);
    }

    if caddy_logpaths.is_empty() && clf_logpaths.is_empty() && generic_paths.is_empty() {
        bail!("no log files to parse, see --help");
    }

    // jail
    let jail = Jail::new(args.allowance, args.jailtime)?;

    let assess_line = |line: Line| {
        let payload = line.line();
        let path_buf = Some(line.source().to_path_buf());
        let path = path_buf.as_ref();

        let (target, ret) = if path.is_some_and(|p| clf_logpaths.contains(p)) {
            ("clf", clf::parse(payload, probelist, invalid_statuses_ref)?)
        } else if path.is_some_and(|p| caddy_logpaths.contains(p)) {
            (
                "caddy",
                caddy::parse(payload, probelist, invalid_statuses_ref)?,
            )
        } else if path.is_some_and(|p| generic_paths.contains(p)) {
            (
                "generic",
                generic::parse(payload, generic_ip_re, generic_positive, generic_negative)?,
            )
        } else {
            bail!("file {:?} unknown ?", path)
        };

        if let ParsingStatus::BadEntry(ip, allowance) = ret {
            if args.verbose {
                log!("{} logged offence for {}", target, ip);
            }
            let banned = jail.sentence(ip, allowance)?;
            if banned {
                log!("{} jailtime for {}", target, ip);
            }
        }

        Ok(())
    };

    loop {
        match ml.next_line().await {
            Ok(Some(line)) => {
                if let Err(e) = assess_line(line) {
                    log!("ERR: {:?}", e);
                }
            }
            Ok(None) => {
                log!("log stream ended, exiting");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
