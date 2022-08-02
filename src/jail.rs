use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use anyhow::*;
use ipset_sys::IpsetSys;

use crate::utils::JailStatus;

pub struct Jail {
    jailtime: u32,
    allowance: u8,
    remand: Mutex<HashMap<IpAddr, u8>>,
    ipset: IpsetSys,
}

const JAIL_NAME: &str = "blockfast_jail";

const ERR_MSG: &str =
    "error using ipset/iptables, maybe it's not installed, this program isn't running as root ?";

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        let init0 = format!(
            "iptables -I INPUT 1 -m set -j DROP --match-set {} src",
            JAIL_NAME
        );
        let init1 = format!(
            "iptables -I FORWARD 1 -m set -j DROP --match-set {} src",
            JAIL_NAME
        );

        let args1: Vec<&str> = init0.split_whitespace().collect();
        let args2: Vec<&str> = init1.split_whitespace().collect();

        // init ipset
        let mut ipset = IpsetSys::init()?;
        let init_cmd = format!("create {} hash:ip timeout 0", JAIL_NAME);
        let _ = ipset.run(&init_cmd);

        // setup input
        let out = Command::new("sudo").args(args1).output()?;
        if out.status.code() != Some(0) {
            eprintln!("{:?}", out);
            bail!(ERR_MSG);
        }

        // setup fwd
        let out = Command::new("sudo").args(args2).output()?;
        if out.status.code() != Some(0) {
            eprintln!("{:?}", out);
            bail!(ERR_MSG);
        }

        Ok(Jail {
            allowance,
            jailtime,
            ipset,
            remand: Mutex::new(HashMap::new()),
        })
    }

    pub fn incr(&mut self, ip: IpAddr) -> Result<JailStatus> {
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
            let sentence = format!(
                "add {} {} timeout {}",
                JAIL_NAME,
                ip.to_string(),
                self.jailtime
            );
            self.ipset.run(&sentence)?;
            Ok(JailStatus::Jailed(ip))
        } else {
            Ok(JailStatus::Remand)
        }
    }
}
