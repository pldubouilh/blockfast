use anyhow::*;
use linemux::MuxedLines;

mod clf;
mod sshd;
mod utils;

mod jail;
use crate::jail::Jail;
use crate::utils::*;

fn judge(
    path_sshd: &str,
    path_clf: &str,
    payload: &str,
    path: &str,
    jail: &Jail,
) -> Result<Judgment> {
    let do_sshd = !path_sshd.is_empty();
    let do_clf = !path_clf.is_empty();
    let mut target = "";

    let ret_parse = if do_sshd && path.ends_with(path_sshd) {
        target = "sshd";
        sshd::parse(payload)
    } else if do_clf && path.ends_with(path_clf) {
        target = "clf ";
        clf::parse(payload)
    } else {
        Err(anyhow!("cant locate file !"))
    };

    let ip = match ret_parse? {
        ParsingStatus::OkEntry => return Ok(Judgment::Good),
        ParsingStatus::BadEntry(ip) => ip,
    };

    match jail.probe(ip)? {
        JailStatus::Remand => Ok(Judgment::Remand),
        JailStatus::Jailed(ip) => Ok(Judgment::Bad(target, ip)),
    }
}

async fn run() -> Result<()> {
    let args = utils::cli().get_matches();
    let mut lines = MuxedLines::new()?;

    // jail
    let jailtime_str = args.value_of("jailtime").unwrap_or("");
    let jailtime = jailtime_str.parse().context("parsing jailtime")?;

    let allowance_str = args.value_of("allowance").unwrap_or("");
    let allowance = allowance_str.parse().context("parsing allowance")?;

    let jail = Jail::new(allowance, jailtime)?;
    eprintln!(
        "+ jail setup, offences allowed: {}, jailtime {}s",
        allowance, jailtime
    );

    // sshd
    let path_sshd = args.value_of("sshd_logpath").unwrap_or("");
    if !path_sshd.is_empty() {
        lines.add_file(path_sshd).await?;
        eprintln!("+ starting with sshd parsing at {}", path_sshd);
    }

    // common log format
    let path_clf = args.value_of("clf_logpath").unwrap_or("");
    if !path_clf.is_empty() {
        lines.add_file(path_clf).await?;
        eprintln!("+ starting with clf parsing at {}", path_clf);
    }

    while let Ok(Some(line)) = lines.next_line().await {
        let payload = line.line();
        let path = line.source().display().to_string();

        match judge(path_sshd, path_clf, payload, &path, &jail) {
            Err(err) => eprintln!("! ERR {:?} - file {}", err, path),
            Ok(Judgment::Good) => {}
            Ok(Judgment::Remand) => {}
            Ok(Judgment::Bad(target, ip)) => {
                eprintln!("~ {} jailtime for: {}", target, ip)
            }
        };
    }

    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let ret = run().await;
    let _ = ret.map_err(|e| eprintln!("! ERROR {:?}", e));
    eprintln!("\n");
    let _ = utils::cli().print_help();
    Ok(())
}
