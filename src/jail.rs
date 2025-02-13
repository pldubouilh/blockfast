use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use anyhow::*;

use crate::utils::{get_epoch, log};

pub struct Jail {
    name: String,
    allowance: u8,
    jailtime: u32,
    remand: Mutex<HashMap<IpAddr, (u8, u64)>>,
}

fn exec(program: &str, cmd: &str, err: &str) -> Result<(), Error> {
    let sentence_sl: Vec<&str> = cmd.split_whitespace().collect();
    let out = Command::new(program).args(sentence_sl).output()?;
    let sc = out.status.code();
    ensure!(sc == Some(0), "err exec {}, {:?}\n{}", cmd, out, err);
    Ok(())
}

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        const ERR_MSG: &str = "error using ipset/iptables, maybe it's not installed, or this program isn't running as root ?";
        let n = format!("blockfast_jail_{}", jailtime);

        // create
        let cmd = format!("create -exist {} hash:ip timeout {}", n, jailtime);
        exec("ipset", &cmd, ERR_MSG)?;

        // setup input
        let cmd = format!("-I INPUT 1 -m set -j DROP --match-set {} src", n);
        exec("iptables", &cmd, ERR_MSG)?;

        // setup fwd
        let cmd = format!("-I FORWARD 1 -m set -j DROP --match-set {} src", n);
        exec("iptables", &cmd, ERR_MSG)?;

        log!("jail setup, allowance {}, time {}s", allowance, jailtime);
        Ok(Jail {
            name: n,
            allowance,
            jailtime,
            remand: Mutex::new(HashMap::new()),
        })
    }

    pub fn sentence(&self, ip: IpAddr) -> Result<bool> {
        let now = get_epoch();

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
            if hits < self.allowance {
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
