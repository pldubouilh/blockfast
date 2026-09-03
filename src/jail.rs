use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::result::Result::Ok;
use std::sync::Mutex;

use anyhow::*;

use crate::utils::{get_epoch, log};

pub struct Jail {
    name: String,
    allowance: u8,
    jailtime: u32,
    remand: Mutex<HashMap<IpAddr, (u8, u64)>>, // ip -> (hits, timestamp)
}

fn exec(program: &str, cmd: &str, err: &str) -> Result<(), Error> {
    let sentence_sl: Vec<&str> = cmd.split_whitespace().collect();
    let out = Command::new(program).args(sentence_sl).output()?;
    let sc = out.status.code();
    ensure!(sc == Some(0), "err exec {}, {:?}\n{}", cmd, out, err);
    Ok(())
}

fn check_installed(program: &str) -> Result<()> {
    match Command::new(program).arg("--version").output() {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("`{}` not found, please install it first", program)
        }
        Err(e) => Err(e).context(format!("cant execute `{}`", program)),
    }
}

fn exec_ok(program: &str, cmd: &str) -> Result<bool> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let out = Command::new(program).args(parts).output()?;
    Ok(out.status.code() == Some(0))
}

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        const ERR_MSG: &str =
            "error using ipset/iptables, maybe this program isn't running as root ?";
        check_installed("ipset")?;
        check_installed("iptables")?;
        let n = format!("blockfast_jail_{}", jailtime);

        // create
        let cmd = format!("create -exist {} hash:ip timeout {}", n, jailtime);
        exec("ipset", &cmd, ERR_MSG)?;

        // install drop rule on INPUT and FORWARD, but only if not already present
        let rule_spec = format!("-m set -j DROP --match-set {} src", n);
        for chain in &["INPUT", "FORWARD"] {
            let check = format!("-C {} {}", chain, rule_spec);
            if !exec_ok("iptables", &check)? {
                let install = format!("-I {} 1 {}", chain, rule_spec);
                exec("iptables", &install, ERR_MSG)?;
            }
        }

        log!("jail setup, allowance {}, time {}s", allowance, jailtime);
        Ok(Jail {
            name: n,
            allowance,
            jailtime,
            remand: Mutex::new(HashMap::new()),
        })
    }

    // allowance_override comes from a matched probe, else the global setting applies
    pub fn sentence(&self, ip: IpAddr, allowance_override: Option<u8>) -> Result<bool> {
        let now = get_epoch();
        let allowance = allowance_override.unwrap_or(self.allowance);

        let should_ban = {
            let mut locked_map = self.remand.lock().map_err(|_| anyhow!("cant lock"))?;

            let (hits, _ts) = *locked_map
                .entry(ip)
                .and_modify(|(hits, ts)| {
                    if now > *ts + self.jailtime as u64 {
                        // reset if we have a hit, but past the defined jailtime
                        *ts = now;
                        *hits = 1;
                    } else {
                        *hits += 1; // bump
                    }
                })
                .or_insert((1, now));
            if hits < allowance {
                false
            } else {
                locked_map.remove_entry(&ip);
                true
            }
        };

        if should_ban {
            let cmd = format!("add -exist {} {}", self.name, ip);
            exec("ipset", &cmd, "")?;
            return Ok(true);
        }

        Ok(false)
    }
}
