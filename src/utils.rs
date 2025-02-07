use anyhow::{anyhow, Context, Result};
use clap::Parser;
use regex::Regex;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum ParsingStatus {
    OkEntry,
    BadEntry(IpAddr),
}

pub fn get_epoch() -> u64 {
    let e = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    e.map(|e| e.as_secs()).unwrap_or(0)
}

macro_rules! log{
    ($first:expr) => {
        let ts = crate::utils::get_epoch();
        eprintln!("{} - {}", ts, $first);
    };
    ($first:expr, $($others:expr),+) => {
        let ts = crate::utils::get_epoch();
        let formatted = format!($first, $($others), *);
        eprintln!("{} - {}", ts, formatted);
    };
}

pub fn resolve_path(a: &str) -> Result<PathBuf> {
    let p = Path::new(a);
    if !p.exists() {
        return Err(anyhow!("path {:?} does not exist", p));
    }
    let p = std::fs::canonicalize(p)?;
    Ok(p)
}

pub fn parse_regex(a: &str) -> Result<Regex> {
    println!("a {:?}", a);
    let r: Regex = Regex::new(a).context("invalid regexp for generic parser")?;
    Ok(r)
}

pub fn parse_statuses(a: &str) -> Result<Vec<u32>> {
    let mut statuses = vec![];
    for s in a.split(',') {
        if s.contains("xx") {
            let range = s.replace("xx", "");
            let range = range.parse::<u32>().context("invalid range")?;
            let range = range * 100;
            for i in 0..100 {
                let status = range + i;
                statuses.push(status);
            }
        } else if s.contains("x") {
            let range = s.replace("x", "");
            let range = range.parse::<u32>().context("invalid range")?;
            let range = range * 10;
            for i in 0..10 {
                let status = range + i;
                statuses.push(status);
            }
        } else {
            let status = s.parse::<u32>().context("invalid status")?;
            statuses.push(status);
        }
    }
    Ok(statuses)
}

pub(crate) use log;

#[derive(Parser, Debug)]
#[command(
    name = "Blockfast",
    author = "pierre dubouilh <pldubouilh@gmail.com>",
    arg_required_else_help = true,
    version,
    long_about = None,
    about = "
Blockfast - block internets scanners fast 🍶
Author: pierre dubouilh <pldubouilh@gmail.com>

Blockfast reads logs from various sources and blocks the offending IPs using iptables and ipset.
It supports logs from sshd, Common-Log-Format (Apache, etc..), JSON (Caddy) and a generic logs parser.

Example:
    # block invalid sshd attempts & invalid http statuses from caddy
    ./blockfast -s=/var/log/auth.log -j=/caddy/logs

    # generic log parser example with a log text to flag, and a regex to parse the offending IP.
    ./blockfast --generic-logpath=/tmp/generictest --generic-positive='Failed password' --generic-ip='from ([0-9a-fA-F:.]+) port'",
    verbatim_doc_comment,
)]

pub struct Args {
    /// jail time (seconds)
    #[clap(long, default_value = "21600")]
    pub jailtime: u32,

    /// how many offences allowed (max 255)
    #[clap(long, default_value = "5")]
    pub allowance: u8,

    /// log all offences
    #[clap(short, long)]
    pub verbose: bool,

    /// path of sshd logfile
    #[clap(short, long, value_parser = resolve_path)]
    pub sshd_logpath: Option<PathBuf>,

    /// path of Common-Log-Format logfile (Apache, etc..)
    #[clap(short, long, value_parser = resolve_path)]
    pub clf_logpath: Option<PathBuf>,

    /// path of JSON logfile (works with Caddy)
    #[clap(short, long, value_parser = resolve_path)]
    pub json_logpath: Option<PathBuf>,

    /// generic parser log file path
    #[clap(long, value_parser = resolve_path)]
    pub generic_logpath: Option<PathBuf>,

    /// generic parser ip regex
    #[clap(long , value_parser = parse_regex)]
    pub generic_ip: Option<Regex>,

    /// generic parser positive - if a logline contains this, it is considered bad, the rest is good
    #[clap(long)]
    pub generic_positive: Option<String>,

    /// generic parser negative - if a logline contains this, it is considered good, the rest is bad
    #[clap(long)]
    pub generic_negative: Option<String>,

    /// valid http statuses (for CLF and JSON logs). Coma separated list, accepts ranges with XX.
    #[clap(long, default_value = "10x,20x,30x,404,408")]
    pub valid_http_statuses: String,
}
