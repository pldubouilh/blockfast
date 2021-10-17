use linemux::MuxedLines;

mod clf;
mod sshd;
mod utils;

mod jail;
use crate::jail::Jail;
use crate::utils::Error;

async fn run() -> Option<()> {
    let args = utils::cli().get_matches();
    let mut lines = MuxedLines::new().ok()?;

    // jail
    let jailtime: u32 = args.value_of("jailtime")?.parse().ok()?;
    let allowance: u8 = args.value_of("allowance")?.parse().ok()?;
    let jail = Jail::new(allowance, jailtime);

    // sshd
    let path_sshd = args.value_of("sshd_logpath").unwrap_or("");
    let do_sshd = !path_sshd.is_empty();
    if do_sshd {
        lines.add_file(path_sshd).await.ok()?;
        eprintln!("+ starting with sshd parsing at {}", path_sshd);
    }

    // common log format
    let path_clf = args.value_of("clf_logpath").unwrap_or("");
    let do_clf = !path_clf.is_empty();
    if do_clf {
        lines.add_file(path_clf).await.ok()?;
        eprintln!("+ starting with clf parsing at {}", path_clf);
    }

    while let Ok(Some(line)) = lines.next_line().await {
        let payload = line.line();
        let path = line.source().display().to_string();

        let res = if do_sshd && path.ends_with(path_sshd) {
            sshd::parse(payload)
        } else if do_clf && path.ends_with(path_clf) {
            clf::parse(payload)
        } else {
            Err(Error::UnknownError)
        };

        if let Ok(Some(ip)) = res {
            jail.probe(ip);
        } else {
            eprintln!("! error processing logline: {}", path);
        }
    }

    Some(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let _ = run().await;
    eprintln!("! ERR");
    let _ = utils::cli().print_help();
    Ok(())
}
