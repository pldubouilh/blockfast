use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgGroup, Parser};
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
    let r: Regex = Regex::new(a).context("invalid regexp for generic parser")?;
    Ok(r)
}

/// Parse a comma-separated list of HTTP statuses with trailing-`x` wildcards.
///
/// Accepted forms per token: `NNN` (literal), `NNx` (10-wide range), `Nxx` (100-wide range).
/// All expanded codes must fall in the valid HTTP range 100..=599.
pub fn parse_statuses(a: &str) -> Result<Vec<u32>> {
    if a.trim().is_empty() {
        bail!("invalid_http_statuses: empty input");
    }
    let mut statuses = vec![];
    for raw in a.split(',') {
        let s = raw.trim();
        let xs = s.chars().rev().take_while(|c| *c == 'x').count();
        let digits = &s[..s.len() - xs];
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            bail!("invalid http status `{}`", s);
        }
        let base: u32 = digits.parse().context("invalid status")?;
        let span = 10u32.pow(xs as u32);
        let from = base * span;
        for code in from..(from + span) {
            if !(100..=599).contains(&code) {
                bail!("status {} out of valid HTTP range (100..=599)", code);
            }
            statuses.push(code);
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
    version = option_env!("BLOCKFAST_VERS").unwrap_or("unknown"),
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
    group(ArgGroup::new("generic_match").args(["generic_positive", "generic_negative"])),
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
    #[clap(long, value_parser = resolve_path, requires_all = ["generic_ip", "generic_match"])]
    pub generic_logpath: Option<PathBuf>,

    /// generic parser ip regex
    #[clap(long, value_parser = parse_regex, requires = "generic_logpath")]
    pub generic_ip: Option<Regex>,

    /// generic parser positive - if a logline contains this, it is considered bad, the rest is good
    #[clap(long, requires = "generic_logpath")]
    pub generic_positive: Option<String>,

    /// generic parser negative - if a logline contains this, it is considered good, the rest is bad
    #[clap(long, requires = "generic_logpath")]
    pub generic_negative: Option<String>,

    /// invalid http statuses (for CLF and JSON logs). Coma separated list, accepts ranges with XX.
    #[clap(long, default_value = "400,401,402,403")]
    pub invalid_http_statuses: String,
}

#[cfg(test)]
mod tests {
    use super::parse_statuses;

    #[test]
    fn literal() {
        assert_eq!(parse_statuses("401").unwrap(), vec![401]);
        assert_eq!(parse_statuses("401,404,429").unwrap(), vec![401, 404, 429]);
    }

    #[test]
    fn ten_range() {
        assert_eq!(
            parse_statuses("40x").unwrap(),
            (400..410).collect::<Vec<_>>()
        );
    }

    #[test]
    fn hundred_range() {
        assert_eq!(
            parse_statuses("4xx").unwrap(),
            (400..500).collect::<Vec<_>>()
        );
    }

    #[test]
    fn mixed() {
        let got = parse_statuses("401, 40x, 5xx").unwrap();
        assert_eq!(got.len(), 1 + 10 + 100);
        assert_eq!(got[0], 401);
        assert!(got.contains(&500));
        assert!(got.contains(&599));
    }

    #[test]
    fn rejects_out_of_range() {
        // 5x → 50..60, none of which are valid HTTP
        assert!(parse_statuses("5x").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_statuses("").is_err());
        assert!(parse_statuses("xxx").is_err());
        assert!(parse_statuses("1x2").is_err());
        assert!(parse_statuses("abc").is_err());
        assert!(parse_statuses("401,,402").is_err());
    }
}
