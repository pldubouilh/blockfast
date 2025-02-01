use clap::{App, Arg};
use std::net::IpAddr;

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
        eprintln!("{} ~ {}", ts, $first);
    };
    ($first:expr, $($others:expr),+) => {
        let ts = crate::utils::get_epoch();
        let formatted = format!($first, $($others), *);
        eprintln!("{} ~ {}", ts, formatted);
    };
}

pub(crate) use log;

pub fn cli() -> App<'static, 'static> {
    App::new("ban internets scanner fast 🍶")
        .version(env!("CARGO_PKG_VERSION"))
        .author("pierre dubouilh <pldubouilh@gmail.com>")
        // .arg(Arg::with_name("prune")
        //     .short("prune")
        //     .help("prune current logfiles to prefill banlist")
        //     .default_value("false")
        //     .takes_value(true))
        .arg(
            Arg::with_name("jailtime")
                .short("j")
                .help("jail time (seconds)")
                .default_value("21600") // 6 hours
                .takes_value(true),
        )
        .arg(
            Arg::with_name("allowance")
                .short("a")
                .help("how many offences allowed (max 255")
                .default_value("5")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sshd_logpath")
                .short("sshd_logpath")
                .help("path of sshd logfile (disable with empty path)")
                .default_value("/var/log/auth.log")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("clf_logpath")
                .short("clf_logpath")
                .help("path of Common-Log-Format (Apache, etc..) logfile")
                .default_value("")
                .takes_value(true),
        )
    // .arg(Arg::with_name("clf_bad_http_codes")
    //     .short("cb")
    //     .help("bad http statuses for CLF")
    //     .default_value([401, 429])
    //     .takes_value(true))
}
