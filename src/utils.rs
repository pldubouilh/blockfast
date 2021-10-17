use clap::{App, Arg};

pub fn cli() -> App<'static, 'static> {
    App::new("ban internets scanner fast 🍶")
        .version("v0.0.1")
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
                .default_value("3600")
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
    //     .help("bad CLF http codes")
    //     .default_value("{401, 429}")
    //     .takes_value(true))
}
