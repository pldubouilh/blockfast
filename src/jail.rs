use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use anyhow::*;

use crate::utils::log;

pub struct Jail {
    name: String,
    allowance: u8,
    remand: Mutex<HashMap<IpAddr, u8>>,
}

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        const ERR_MSG: &str = "error using ipset/iptables, maybe it's not installed, this program isn't running as root ?";
        let n = format!("blockfast_jail_{}", jailtime);

        let i0 = format!("ipset create -exist {} hash:ip timeout {}", n, jailtime);
        let i1 = format!("iptables -I INPUT 1 -m set -j DROP --match-set {} src", n);
        let i2 = format!("iptables -I FORWARD 1 -m set -j DROP --match-set {} src", n);

        let args0: Vec<&str> = i0.split_whitespace().collect();
        let args1: Vec<&str> = i1.split_whitespace().collect();
        let args2: Vec<&str> = i2.split_whitespace().collect();

        // create
        let out = Command::new("sudo").args(args0).output()?;
        ensure!(out.status.code() == Some(0), "{}: {:?}", ERR_MSG, out);

        // setup input
        let out = Command::new("sudo").args(args1).output()?;
        ensure!(out.status.code() == Some(0), "{}: {:?}", ERR_MSG, out);

        // setup fwd
        let out = Command::new("sudo").args(args2).output()?;
        ensure!(out.status.code() == Some(0), "{}: {:?}", ERR_MSG, out);

        log!("jail setup, allowance {}, time {}s", allowance, jailtime);
        Ok(Jail {
            name: n,
            allowance,
            remand: Mutex::new(HashMap::new()),
        })
    }

    pub fn sentence(&self, ip: IpAddr, target: &str) -> Result<()> {
        let should_ban = {
            let mut locked_map = self.remand.lock().map_err(|_| anyhow!("cant lock"))?;

            // TODO: set time of last offence, and add grace
            let hits = *locked_map.entry(ip).and_modify(|e| *e += 1).or_insert(1);

            if hits < self.allowance {
                false
            } else {
                locked_map.remove_entry(&ip); // preserve space
                true
            }
        };

        if should_ban {
            log!("{} jailtime for: {}", target, ip);
            let sentence = format!("ipset add -exist {} {}", self.name, ip);
            let sentence_sl: Vec<&str> = sentence.split_whitespace().collect();

            let out = Command::new("sudo").args(sentence_sl).output()?;
            let stderr = std::str::from_utf8(&out.stderr)?;
            ensure!(out.status.code() == Some(0), "executing ban {}", stderr);
        }

        Ok(())
    }
}
